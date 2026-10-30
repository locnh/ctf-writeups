from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from utils.db import database as db
from utils.models import User, Transaction, Loan
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
import math

api_bp = Blueprint('api', __name__)

# Static exchange rates (example rates). The reverse rate is derived from the forward rate
# so that a round trip can never return more than it started with.
SCHMECKLE_TO_BLEMFLARK = 0.72
EXCHANGE_RATES = {
    'Schmeckle': {'Blemflark': SCHMECKLE_TO_BLEMFLARK, 'Schmeckle' : 1},
    'Blemflark': {'Schmeckle': 1 / SCHMECKLE_TO_BLEMFLARK, 'Blemflark' : 1}
}

def is_valid_amount(amount):
    # Reject NaN, infinity and zero/negative values
    return math.isfinite(amount) and amount > 0

# Mock Bank Capital for Loans
BANK_CAPITAL = 500_000_000_000  # 500 billion Schmeckle

@api_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    
    if not username or not password or not email:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400
    
    # Check if user already exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'success': False, 'message': 'Username or email already exists.'}), 401
    
    # Create new user
    new_user = User(
        username=username,
        email=email,
        role='normal',
        schmeckle_balance=10_000.0,  # Initial user Schmeckle balance
        blemflark_balance=5_000.0  # Initial user Blemflark balance
    )
    new_user.set_password(password)
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User registered successfully.'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Database integrity error.'}), 500
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred during registration.'}), 500
    
@api_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400
    
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password) and user.role != 'pending_closure':
        access_token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=1))
        user_data = user.to_dict()
        return jsonify({'success': True, 'access_token': access_token, 'user': user_data}), 200
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials.'}), 401

@api_bp.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    users_list = []
    for user in users:
        if user.username != User.query.get(get_jwt_identity()).username:
            users_list.append({'username': user.username})
    
    return jsonify({'success': True, 'users': users_list}), 200

@api_bp.route('/balance', methods=['GET'])
@jwt_required()
def get_balance():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    return jsonify({
        'success': True,
        'balances': {
            'schmeckle_balance': user.schmeckle_balance,
            'blemflark_balance': user.blemflark_balance
        }
    }), 200

@api_bp.route('/transactions', methods=['GET'])
@jwt_required()
def get_transactions():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    user_id = int(user_id)
    
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user_id) | (Transaction.recipient_id == user_id)
    ).order_by(Transaction.timestamp.desc()).all()
    
    transactions_list = []
    for tx in transactions:
        tx_type = ['exchange', 'send', 'receive'][[tx.sender_id == tx.recipient_id, (tx.sender_id == user_id and tx.recipient_id != user_id), (tx.sender_id != user_id and tx.recipient_id == user_id)].index(True)]
        
        counterparty = tx.recipient.username if tx.sender_id == user_id else tx.sender.username
        transactions_list.append({
            'date': tx.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'type': tx_type,
            'amount': tx.amount,
            'currency': tx.currency.lower(),
            'counterparty': counterparty
        })
    
    return jsonify({'success': True, 'transactions': transactions_list}), 200

@api_bp.route('/send_money', methods=['POST'])
@jwt_required()
def send_money():
    user_id = get_jwt_identity()
    data = request.get_json()
    recipient_username = data.get('recipient_username')
    amount = data.get('amount')
    currency = data.get('currency')  # New field to specify currency

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400
    
    if not recipient_username or not amount or not currency:
        return jsonify({'success': False, 'message': 'Recipient, amount, and currency are required.'}), 400

    if not is_valid_amount(amount):
        return jsonify({'success': False, 'message': 'Amount must be positive.'}), 400

    sender = User.query.get(user_id)
    recipient = User.query.filter_by(username=recipient_username).first()
    
    if not recipient:
        return jsonify({'success': False, 'message': 'Recipient not found.'}), 404
    
    
    if currency == 'schmeckle':
        if sender.schmeckle_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient Schmeckle balance.'}), 400
        sender.schmeckle_balance -= amount
        recipient.schmeckle_balance += amount

    elif currency == 'blemflark':
        if sender.blemflark_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient Blemflark balance.'}), 400
        sender.blemflark_balance -= amount
        recipient.blemflark_balance += amount

    else:
        return jsonify({'success': False, 'message': 'Unsupported currency.'}), 400
    
    transaction = Transaction(
        sender_id=user_id,
        recipient_id=recipient.id,
        amount=amount,
        type='send_money',
        currency=currency,  # Record the currency used
        timestamp=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(transaction)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Money sent successfully.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred during the transaction.'}), 500

@api_bp.route('/exchange', methods=['POST'])
@jwt_required()
def exchange_currency():
    user_id = get_jwt_identity()
    data = request.get_json()
    from_currency = data.get('from_currency')
    to_currency = data.get('to_currency')
    amount = data.get('amount')

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400    
    
    if not from_currency or not to_currency or not amount:
        return jsonify({'success': False, 'message': 'All fields are required.'}), 400
    
    if not is_valid_amount(amount):
        return jsonify({'success': False, 'message': 'Amount must be positive.'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404

    if from_currency == to_currency:
        return jsonify({'success': False, 'message': 'Currencies must be different.'}), 400
    
    if from_currency not in EXCHANGE_RATES or to_currency not in EXCHANGE_RATES[from_currency]:
        return jsonify({'success': False, 'message': 'Exchange rate not available.'}), 400
    
    rate = EXCHANGE_RATES[from_currency][to_currency]
    exchanged_amount = amount * rate

    if from_currency == 'Schmeckle':
        if user.schmeckle_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient Schmeckle balance.'}), 400
        user.schmeckle_balance -= amount
        user.blemflark_balance += exchanged_amount
    elif from_currency == 'Blemflark':
        if user.blemflark_balance < amount:
            return jsonify({'success': False, 'message': 'Insufficient Blemflark balance.'}), 400
        user.blemflark_balance -= amount
        user.schmeckle_balance += exchanged_amount
    else:
        return jsonify({'success': False, 'message': 'Unsupported currency.'}), 400
    
    transaction = Transaction(
        sender_id=user_id,
        recipient_id=user_id,
        amount=exchanged_amount if from_currency == 'Schmeckle' else amount,
        type='exchange',
        currency=from_currency,
        timestamp=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(transaction)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Exchanged {amount} {from_currency} to {exchanged_amount} {to_currency}.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred during currency exchange.'}), 500

@api_bp.route('/exchange/history', methods=['GET'])
@jwt_required()
def get_exchange_history():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    transactions = Transaction.query.filter_by(sender_id=user_id, type='exchange').order_by(Transaction.timestamp.desc()).all()
    
    transactions_list = []

    for tx in transactions:
        to_currency = 'Schmeckle' if tx.currency == 'Blemflark' else 'Blemflark'
        transactions_list.append({
            'date': tx.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'amount': tx.amount if tx.currency == 'Schmeckle' else tx.amount * EXCHANGE_RATES['Blemflark']['Schmeckle'],
            'from_currency' : tx.currency,
            'to_currency' : to_currency
        })
    
    return jsonify({'success': True, 'exchanges': transactions_list}), 200

@api_bp.route('/close_account', methods=['POST'])
@jwt_required()
def close_account():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    if user.role == 'administrator':
        return jsonify({'success': False, 'message': 'Administrators cannot close their accounts.'}), 400
    
    # Mark account for closure by setting role to 'pending_closure'
    user.role = 'pending_closure'
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Account closure requested. Awaiting administrator approval.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while requesting account closure.'}), 500

@api_bp.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    user_id = get_jwt_identity()
    loans = Loan.query.filter_by(borrower_id=user_id).all()
    total_amount_borrowed = sum([loan.amount for loan in loans if loan.status == 'approved'])
    
    loans_list = []
    for loan in loans:
        loans_list.append({
            'id': loan.id,
            'user_id': loan.borrower_id,
            'amount': loan.amount,
            'term_months': loan.term_months,
            'status': loan.status,
            'request_date': loan.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'approval_date': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if loan.status == 'approved' else 'N/A',
        })
    
    return jsonify({'success': True, 'loans': loans_list, 'balance' : total_amount_borrowed}), 200

@api_bp.route('/available_amount', methods=['GET'])
@jwt_required()
def get_available_amount():
    return jsonify({'success': True, 'available_amount': BANK_CAPITAL}), 200

@api_bp.route('/loans', methods=['POST'])
@jwt_required()
def request_loan():
    global BANK_CAPITAL
    user_id = get_jwt_identity()
    data = request.get_json()
    amount = data.get('amount')
    term_months = data.get('term_months', 12)  # Default term

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount.'}), 400    
    
    if not is_valid_amount(amount):
        return jsonify({'success': False, 'message': 'Valid loan amount is required.'}), 400
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    # Check loan limits based on user role
    role = user.role if user.role != 'pending_promotion' else 'normal'

    if role == 'premium':
        max_loan = 10_000_000  # Premium users can borrow above 10 million Schmeckle
    elif role == 'normal':
        max_loan = 1_000_000  # Normal users can borrow up to 1 million Schmeckle
    elif role == 'administrator':
        # Administrators cannot request loans since their capital is unlimited
        return jsonify({'success': False, 'message': 'Administrators cannot request loans.'}), 403
    else:
        return jsonify({'success': False, 'message': 'Only registered users can request loans.'}), 403
    
    if amount > max_loan:
        return jsonify({'success': False, 'message': f'Loan amount exceeds your limit of {max_loan} Schmeckle.'}), 400
    
    if BANK_CAPITAL < amount:
        return jsonify({'success': False, 'message': 'Bank has insufficient capital for this loan.'}), 400
    
    # Create loan request with status 'pending'
    loan = Loan(
        borrower_id=user_id,
        amount=amount,
        term_months=term_months,
        interest_rate=5.0,  # Static interest rate
        status='pending',
        created_at=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(loan)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Loan requested successfully. Awaiting approval.'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while requesting the loan.'}), 500


@api_bp.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    return jsonify({'success': True, 'user': user.to_dict()}), 200


@api_bp.route('/profile/promote', methods=['POST'])
@jwt_required()
def promote():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found.'}), 404
    
    if user.role != 'normal':
        return jsonify({'success': False, 'message': 'Promotion is only available for normal users.'}), 400
    
    if user.schmeckle_balance < 1000:
        return jsonify({'success': False, 'message': 'Insufficient Schmeckle balance for promotion.'}), 400

    user.role = 'pending_promotion'
    user.schmeckle_balance -= 1000  # Deduct 1000 Schmeckle for promotion
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': 'Promotion requested successfully. Awaiting administrator approval.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while requesting promotion.'}), 500 
    
# Admin Routes
@api_bp.route('/admin/promotion_requests', methods=['GET'])
@jwt_required()
def get_promotion_requests():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    promotion_users = User.query.filter_by(role='pending_promotion').all()
    users_list = []

    for index, pu in enumerate(promotion_users):
        users_list.append({
            'id': index + 1,
            'user_id': pu.id,
            'username': pu.username,
            'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
            })
    
    return jsonify({'success': True, 'users': users_list}), 200

@api_bp.route('/admin/closure_requests', methods=['GET'])
@jwt_required()
def get_close_requests():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    closure_users = User.query.filter_by(role='pending_closure').all()
    users_list = []
    for index, cu in enumerate(closure_users):
        users_list.append({
            'id': index + 1,
            'user_id': cu.id,
            'username': cu.username,
            'request_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'success': True, 'users': users_list}), 200


@api_bp.route('/admin/loan_requests', methods=['GET'])
@jwt_required()
def get_loan_requests():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    loan_requests = Loan.query.filter_by(status='pending').all()
    loans_list = []
    for lr in loan_requests:
        borrower = User.query.get(lr.borrower_id)
        loans_list.append({
            'id': lr.id,
            'username': borrower.username,
            'amount' : lr.amount,
            'term_months' : lr.term_months,
            'status' : lr.status,
            'request_date' : lr.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'success': True, 'loans': loans_list}), 200


@api_bp.route('/admin/stats', methods=['GET'])
@jwt_required()
def get_stats():
    # Fetching total users, total transactions, premiumUsers and total loans
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or user.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    total_users = User.query.count()
    total_transactions = Transaction.query.count()
    premium_users = User.query.filter_by(role='premium').count()
    total_loans = Loan.query.filter_by(status='approved').count()

    stats = {
            'total_users': total_users,
            'total_transactions': total_transactions,
            'premium_users': premium_users,
            'total_loans': total_loans
            }

    return jsonify({
        'success': True,
        'stats': stats,
    }), 200


@api_bp.route('/admin/approve_promotion', methods=['POST'])
@jwt_required()
def approve_promotion():
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    if not admin or admin.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    data = request.get_json()
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({'success': False, 'message': 'User ID is required.'}), 400
    
    user = User.query.get(target_user_id)
    if not user or user.role != 'pending_promotion':
        return jsonify({'success': False, 'message': 'Promotion request not found for the user.'}), 404
    
    # Promote user to premium
    user.role = 'premium'
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'User {user.username} promoted to premium.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while promoting the user.'}), 500

@api_bp.route('/admin/reject_promotion', methods=['POST'])
@jwt_required()
def reject_promotion():
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    if not admin or admin.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    data = request.get_json()
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({'success': False, 'message': 'User ID is required.'}), 400
    
    user = User.query.get(target_user_id)
    if not user or user.role != 'pending_promotion':
        return jsonify({'success': False, 'message': 'Promotion request not found for the user.'}), 404
    
    # Reject promotion by reverting role to 'normal'
    user.role = 'normal'
    user.schmeckle_balance += 1000  # Refund the promotion fee
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'Promotion request for user {user.username} has been rejected.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while rejecting the promotion.'}), 500

@api_bp.route('/admin/approve_closure', methods=['POST'])
@jwt_required()
def approve_closure():
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    if not admin or admin.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    data = request.get_json()
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({'success': False, 'message': 'User ID is required.'}), 400
    
    user = User.query.get(target_user_id)
    if not user or user.role != 'pending_closure':
        return jsonify({'success': False, 'message': 'Account closure request not found for the user.'}), 404
    
    # Close the account by deleting the user
    db.session.delete(user)
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'User {user.username} account closed.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while closing the account.'}), 500
    
@api_bp.route('/admin/reject_closure', methods=['POST'])
@jwt_required()
def reject_closure():
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    if not admin or admin.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    data = request.get_json()
    target_user_id = data.get('user_id')
    
    if not target_user_id:
        return jsonify({'success': False, 'message': 'User ID is required.'}), 400
    
    user = User.query.get(target_user_id)
    if not user or user.role != 'pending_closure':
        return jsonify({'success': False, 'message': 'Account closure request not found for the user.'}), 404
    
    # Reject account closure by reverting role to 'normal'
    user.role = 'normal'
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'Account closure request for user {user.username} has been rejected.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while rejecting the account closure.'}), 500

@api_bp.route('/admin/approve_loan', methods=['POST'])
@jwt_required()
def approve_loan():
    global BANK_CAPITAL
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    if not admin or admin.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    data = request.get_json()
    loan_id = data.get('loan_id')
    
    if not loan_id:
        return jsonify({'success': False, 'message': 'Loan ID is required.'}), 400
    
    loan = Loan.query.get(loan_id)
    if not loan or loan.status != 'pending':
        return jsonify({'success': False, 'message': 'Loan request not found or already processed.'}), 404
    
    borrower = User.query.get(loan.borrower_id)
    if not borrower:
        return jsonify({'success': False, 'message': 'Borrower not found.'}), 404
    
    # Check if BANK_CAPITAL is sufficient
    if BANK_CAPITAL < loan.amount:
        return jsonify({'success': False, 'message': 'Bank has insufficient capital to approve this loan.'}), 400
    
    # Approve the loan
    loan.status = 'approved'
    borrower.schmeckle_balance += loan.amount
    BANK_CAPITAL -= loan.amount
    
    # Record the transaction as loan disbursement
    transaction = Transaction(
        sender_id=user_id,  # None indicates it's a system transaction
        recipient_id=borrower.id,
        amount=loan.amount,
        type='loan_disbursement',
        timestamp=datetime.now(timezone.utc)
    )
    
    try:
        db.session.add(transaction)
        db.session.commit()
        return jsonify({'success': True, 'message': f'Loan ID {loan.id} approved and disbursed to {borrower.username}.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while approving the loan.'}), 500

@api_bp.route('/admin/reject_loan', methods=['POST'])
@jwt_required()
def reject_loan():
    user_id = get_jwt_identity()
    admin = User.query.get(user_id)
    
    if not admin or admin.role != 'administrator':
        return jsonify({'success': False, 'message': 'Administrator access required.'}), 403
    
    data = request.get_json()
    loan_id = data.get('loan_id')
    
    if not loan_id:
        return jsonify({'success': False, 'message': 'Loan ID is required.'}), 400
    
    loan = Loan.query.get(loan_id)
    if not loan or loan.status != 'pending':
        return jsonify({'success': False, 'message': 'Loan request not found or already processed.'}), 404
    
    # Reject the loan
    loan.status = 'rejected'
    
    try:
        db.session.commit()
        return jsonify({'success': True, 'message': f'Loan ID {loan.id} has been rejected.'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'An error occurred while rejecting the loan.'}), 500
