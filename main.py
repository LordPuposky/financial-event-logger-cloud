"""
Financial Transaction Event Logger & Audit Trail Service
Author: Yesid Augusto Romero Ruiz
Course: CSE 310 - Applied Programming (Module 3: Cloud Databases)

This software integrates Google Cloud Firestore to simulate a real-time banking
event ingestion pipeline, compliance audit querying, status updating, and
automated anomaly detection (stretch challenge).
"""

import sys
import os
from datetime import datetime, timezone
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1.base_query import FieldFilter


def initialize_firestore_client():
    """
    Initializes the Firebase Admin SDK connection using a local service account key.
    Returns:
        firestore.Client: An active Firestore client instance.
    """
    credential_file = "serviceAccountKey.json"

    if not os.path.exists(credential_file):
        print(f"[ERROR] Service account file '{credential_file}' not found.")
        print("Please place your Firebase Admin SDK JSON key in the project root.")
        sys.exit(1)

    try:
        cred = credentials.Certificate(credential_file)
        # Avoid re-initializing if already loaded
        if not firebase_admin._apps:
            firebase_admin.initialize_app(cred)
        db = firestore.client()
        print("[SUCCESS] Successfully connected to Google Cloud Firestore.")
        return db
    except Exception as error:
        print(f"[FATAL] Failed to connect to Firestore: {error}")
        sys.exit(1)


def log_transaction_event(db, account_id, amount, tx_type, ip_address):
    """
    Records a new financial transaction event document in the 'transaction_events' collection.
    Automatically triggers anomaly detection if business rules are met.

    Args:
        db (firestore.Client): Active database client.
        account_id (str): Unique bank account identifier.
        amount (float): Transaction financial amount.
        tx_type (str): Type of operation (e.g., DEPOSIT, TRANSFER, WITHDRAWAL).
        ip_address (str): Origin IP address of the client transaction.
    """
    try:
        now_utc = datetime.now(timezone.utc)
        initial_status = "PENDING_REVIEW" if amount >= 10000.0 else "APPROVED"

        event_payload = {
            "account_id": account_id.strip().upper(),
            "amount": float(amount),
            "transaction_type": tx_type.strip().upper(),
            "ip_address": ip_address.strip(),
            "status": initial_status,
            "created_at": now_utc
        }

        # Save document to the transaction_events collection
        doc_ref = db.collection("transaction_events").document()
        doc_ref.set(event_payload)

        print(f"[OK] Transaction logged successfully with ID: {doc_ref.id}")
        print(f"     Status: {initial_status} | Account: {event_payload['account_id']} | Amount: ${amount:,.2f}")

        # Stretch Challenge: Evaluate anomaly rule immediately
        trigger_anomaly_detection_rule(db, account_id, amount, doc_ref.id)

    except Exception as err:
        print(f"[ERROR] Failed to record transaction: {err}")


def trigger_anomaly_detection_rule(db, account_id, amount, transaction_id):
    """
    Stretch Challenge: Automated risk detection rule.
    Analyzes transaction properties and writes an alert document to 'account_alerts'
    if high-risk conditions are detected (e.g., amount >= $10,000).

    Args:
        db (firestore.Client): Firestore instance.
        account_id (str): Bank account number.
        amount (float): Transacted amount.
        transaction_id (str): Origin transaction reference ID.
    """
    try:
        HIGH_VALUE_THRESHOLD = 10000.0
        if amount >= HIGH_VALUE_THRESHOLD:
            alert_data = {
                "account_id": account_id.strip().upper(),
                "triggered_by_tx": transaction_id,
                "risk_level": "HIGH",
                "reason": f"High value transaction detected: ${amount:,.2f} exceeds threshold.",
                "resolved": False,
                "timestamp": datetime.now(timezone.utc)
            }
            alert_ref = db.collection("account_alerts").document()
            alert_ref.set(alert_data)
            print(f"[ALERT GENERATED] High-risk anomaly logged in 'account_alerts' (Alert ID: {alert_ref.id})")
    except Exception as alert_err:
        print(f"[WARNING] Anomaly check could not complete: {alert_err}")


def query_all_transactions(db, limit_count=10):
    """
    Fetches the most recent transaction events sorted chronologically.

    Args:
        db (firestore.Client): Firestore instance.
        limit_count (int): Maximum number of records to retrieve.
    """
    try:
        print(f"\n--- Retrieving Last {limit_count} Financial Transactions ---")
        query = (
            db.collection("transaction_events")
            .order_by("created_at", direction=firestore.Query.DESCENDING)
            .limit(limit_count)
        )
        results = query.stream()

        count = 0
        for doc in results:
            data = doc.to_dict()
            created = data.get("created_at")
            time_str = created.strftime("%Y-%m-%d %H:%M:%S UTC") if created else "N/A"
            print(f"ID: {doc.id}")
            print(f"  Account: {data.get('account_id')} | Type: {data.get('transaction_type')} | Amount: ${data.get('amount'):,.2f}")
            print(f"  Status: {data.get('status')} | IP: {data.get('ip_address')} | Time: {time_str}")
            print("-" * 65)
            count += 1

        if count == 0:
            print("No transactions found in database.")
    except Exception as err:
        print(f"[ERROR] Could not query transactions: {err}")


def query_transactions_by_account(db, account_id):
    """
    Queries documents filtered by a specific account number.

    Args:
        db (firestore.Client): Firestore client instance.
        account_id (str): Account identifier to filter by.
    """
    try:
        acc_target = account_id.strip().upper()
        print(f"\n--- Audit Trail for Account: {acc_target} ---")
        query = db.collection("transaction_events").where(
            filter=FieldFilter("account_id", "==", acc_target)
        )
        docs = list(query.stream())

        if not docs:
            print(f"No records found for account '{acc_target}'.")
            return

        for doc in docs:
            data = doc.to_dict()
            print(f"Doc ID: {doc.id} | Amount: ${data.get('amount'):,.2f} | Status: {data.get('status')} | Type: {data.get('transaction_type')}")
    except Exception as err:
        print(f"[ERROR] Failed querying by account: {err}")


def update_transaction_status(db, doc_id, new_status):
    """
    Modifies an existing transaction event status in the cloud database.

    Args:
        db (firestore.Client): Firestore client instance.
        doc_id (str): Document ID to update.
        new_status (str): Target status (e.g., FLAGGED_FRAUD, RESOLVED, APPROVED).
    """
    try:
        valid_statuses = ["APPROVED", "PENDING_REVIEW", "FLAGGED_FRAUD", "RESOLVED"]
        normalized_status = new_status.strip().upper()

        if normalized_status not in valid_statuses:
            print(f"[INVALID] Status must be one of: {', '.join(valid_statuses)}")
            return

        doc_ref = db.collection("transaction_events").document(doc_id.strip())
        doc_snap = doc_ref.get()

        if not doc_snap.exists:
            print(f"[NOT FOUND] Transaction with Document ID '{doc_id}' does not exist.")
            return

        doc_ref.update({
            "status": normalized_status,
            "last_updated_at": datetime.now(timezone.utc)
        })
        print(f"[SUCCESS] Document '{doc_id}' status updated to -> {normalized_status}")
    except Exception as err:
        print(f"[ERROR] Failed to update transaction status: {err}")


def query_system_alerts(db):
    """
    Queries and displays all automated risk alerts generated by the system.

    Args:
        db (firestore.Client): Firestore instance.
    """
    try:
        print("\n--- Compliance & Security Alerts (account_alerts) ---")
        alerts = db.collection("account_alerts").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(10).stream()

        found = False
        for alert in alerts:
            data = alert.to_dict()
            ts = data.get("timestamp")
            t_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "N/A"
            print(f"Alert ID: {alert.id}")
            print(f"  Account: {data.get('account_id')} | Level: {data.get('risk_level')}")
            print(f"  Reason: {data.get('reason')}")
            print(f"  Triggered By Tx: {data.get('triggered_by_tx')} | Time: {t_str}")
            print("-" * 65)
            found = True

        if not found:
            print("No security alerts currently registered.")
    except Exception as err:
        print(f"[ERROR] Failed to query alerts: {err}")


def display_menu():
    """Prints the command line interface navigation menu."""
    print("\n" + "=" * 55)
    print("  FINANCIAL TRANSACTION CLOUD EVENT LOGGER (FIRESTORE)  ")
    print("=" * 55)
    print("1. Log New Financial Transaction Event")
    print("2. View Recent Transaction Logs")
    print("3. Query Audit Trail by Account ID")
    print("4. Update Transaction Status (Review/Fraud/Resolved)")
    print("5. View Automated Security Alerts (Stretch Challenge)")
    print("6. Exit Application")
    print("=" * 55)


def main():
    """Main program loop and CLI controller."""
    print("Starting Financial Transaction Event Logger...")
    db = initialize_firestore_client()

    while True:
        display_menu()
        choice = input("Select an option (1-6): ").strip()

        if choice == "1":
            account = input("Enter Account ID (e.g., ACC-1092): ").strip()
            amount_str = input("Enter Transaction Amount (USD): ").strip()
            try:
                amount = float(amount_str)
            except ValueError:
                print("[ERROR] Invalid numeric amount.")
                continue
            tx_type = input("Enter Type (DEPOSIT/WITHDRAWAL/TRANSFER): ").strip()
            ip = input("Enter Origin IP Address (e.g., 192.168.1.45): ").strip()
            log_transaction_event(db, account, amount, tx_type, ip)

        elif choice == "2":
            query_all_transactions(db, limit_count=10)

        elif choice == "3":
            account = input("Enter Account ID to search: ").strip()
            query_transactions_by_account(db, account)

        elif choice == "4":
            doc_id = input("Enter Transaction Document ID to update: ").strip()
            new_status = input("Enter New Status (APPROVED/FLAGGED_FRAUD/RESOLVED): ").strip()
            update_transaction_status(db, doc_id, new_status)

        elif choice == "5":
            query_system_alerts(db)

        elif choice == "6":
            print("Exiting application. Goodbye!")
            break

        else:
            print("[INVALID] Please select a number from 1 to 6.")


if __name__ == "__main__":
    main()