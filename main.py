from flask import Flask, request, jsonify
import smtplib
import dns.resolver
import random
import string
import time
from concurrent.futures import ThreadPoolExecutor
from dns.exception import DNSException
import logging
from functools import lru_cache

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Constants
SMTP_TIMEOUT = 40
SCRIPT_TIMEOUT = 20000
WORKER_THREADS = 50

# Initialize ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=WORKER_THREADS)

# Caching MX records to reduce DNS lookups
@lru_cache(maxsize=1024)
def get_mx_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.lifetime = SMTP_TIMEOUT
    try:
        mx_records = resolver.resolve(domain, 'MX')
        return str(mx_records[0].exchange)
    except dns.resolver.NoAnswer:
        app.logger.error(f"No MX records found for {domain}")
    except dns.resolver.NXDOMAIN:
        app.logger.error(f"Domain does not exist: {domain}")
    except DNSException as e:
        app.logger.error(f"DNS query failed for {domain}: {e}")
    return None

def is_catch_all(mx_record, domain):
    try:
        with smtplib.SMTP(mx_record, 25, timeout=SMTP_TIMEOUT) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('radam@paidclient.com')
            random_address = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + '@' + domain
            code, _ = server.rcpt(random_address)
            return code == 250
    except Exception as e:
        app.logger.error(f"Catch-all check failed for {domain}: {e}")
        return False

def smtp_handshake(mx_record, email):
    try:
        with smtplib.SMTP(mx_record, 25, timeout=SMTP_TIMEOUT) as server:
            server.set_debuglevel(0)
            server.ehlo()
            server.mail('radam@paidclient.com')
            code, message = server.rcpt(email)
            if code == 250:
                return True, None
            else:
                error_message = message.decode('utf-8') if message else 'Unknown error'
                return False, error_message
    except smtplib.SMTPServerDisconnected:
        return False, "SMTP server disconnected unexpectedly"
    except smtplib.SMTPResponseException as e:
        error_message = f"{e.smtp_code}, {e.smtp_error.decode('utf-8')}"
        return False, error_message
    except Exception as e:
        return False, f"SMTP handshake failed: {str(e)}"

def categorize_email(is_valid, is_catch_all, error=None):
    if error or not is_valid:
        return 'Risky'
    return 'Good' if is_valid and not is_catch_all else 'Risky'

def check_timeout(start_time):
    if time.time() - start_time > SCRIPT_TIMEOUT:
        raise Exception("Script execution exceeded time limit")

def process_single_email(email):
    result = {
        "email": email,
        "category": "Bad",
        "valid": "Invalid",
        "catch_all": "Unknown",
        "error": "Initial error state"
    }

    domain = email.split('@')[-1]
    mx_record = get_mx_record(domain)
    if not mx_record:
        result["error"] = f"No MX records found for {domain}"
        return result

    is_valid, error_message = smtp_handshake(mx_record, email)
    catch_all_status = is_catch_all(mx_record, domain) if is_valid else False

    result.update({
        "category": categorize_email(is_valid, catch_all_status, error=error_message),
        "valid": "Valid" if is_valid else "Invalid",
        "catch_all": "Yes" if catch_all_status else "No",
        "error": error_message if error_message else None
    })

    return result



@app.route('/email_verification', methods=['POST'])
def email_verification():
    try:
        start_time = time.time()
        app.logger.info("Email verification started")

        request_json = request.get_json()
        if not request_json or 'emails' not in request_json:
            return jsonify({"error": "No email addresses provided"}), 400

        emails = request_json['emails']
        future_results = [executor.submit(process_single_email, email) for email in emails]
        results = []
        for future in future_results:
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                app.logger.error(f"Error in thread execution: {e}")
                results.append({
                    "email": "unknown",
                    "category": "Risky",
                    "valid": "Unknown",
                    "catch_all": "Unknown",
                    "error": "Thread execution failed"
                })

        end_time = time.time()
        total_time = end_time - start_time
        app.logger.info(f"Email verification completed in {total_time:.2f} seconds")

        return jsonify({
            "results": results,
            "execution_time": f"{total_time:.2f} seconds"
        })
    except Exception as e:
        app.logger.error(f"Unhandled exception during email verification: {e}")
        return jsonify({"error": "An unexpected error occurred during email verification", "details": str(e)}), 500


@app.errorhandler(Exception)
def handle_general_exception(error):
    app.logger.error(f"Unhandled exception: {error}")
    return jsonify({"error": "An unexpected error occurred", "details": str(error)}), 500

if __name__ == "__main__":
    app.run(debug=True)
