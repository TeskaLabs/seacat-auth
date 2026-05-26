#!/usr/bin/env python3
"""
Reset a user's password via CLI.

Run from the repository root (or pass absolute path)::

    python scripts/reset-password.py -c /path/to/seacatauth.conf

"""

import argparse
import configparser
import contextlib
import getpass
import os
import sys

import pymongo
import argon2
import re


def load_mongodb_config(config_path):
    """Load MongoDB configuration from a config file.

    Args:
        config_path (str): Path to the config file.

    Returns:
        tuple: (mongodb_uri, mongodb_db) configuration values.

    Raises:
        FileNotFoundError: If config_path is not a regular file.
        RuntimeError: If the [mongo] section or required keys are missing.
    """
    if not os.path.isfile(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    parser = configparser.ConfigParser()
    parser.read(config_path)
    files_read = parser.read(config_path)
    if not files_read:
        raise RuntimeError(f"Failed to read config file: {config_path}")
    if 'mongo' not in parser:
        raise RuntimeError(f"Missing [mongo] section in config {config_path}")
    mongodb_uri = parser['mongo'].get('uri')
    mongodb_db = parser['mongo'].get('database')
    if not mongodb_uri or not mongodb_db:
        raise RuntimeError(f"Missing 'uri' or 'database' in [mongo] section of {config_path}")
    return mongodb_uri, mongodb_db


@contextlib.contextmanager
def mongodb_database(mongodb_uri, mongodb_db):
    """Open one MongoDB client for the lifetime of the context.

    Args:
        mongodb_uri (str): MongoDB connection URI.
        mongodb_db (str): MongoDB database name.

    Yields:
        pymongo.database.Database: The configured database.
    """
    client = pymongo.MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
    try:
        yield client[mongodb_db]
    finally:
        client.close()


def find_user(db, username):
    """Find a user by username in the credentials collection.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        username (str): Username to search for.

    Returns:
        dict or None: User document if found, None otherwise.
    """
    collection = db["c"]
    # Try exact match first
    user = collection.find_one({"username": username})
    if user:
        return user
    # Try case-insensitive match
    user = collection.find_one({
        "username": {"$regex": f"^{re.escape(username)}$", "$options": "i"}
    })
    return user


def display_user_info(user):
    """Display user information for confirmation.

    Args:
        user (dict): User document from MongoDB.
    """
    print("\nUser found:")
    print("  ID:        ", user.get("_id"))
    print("  Username:  ", user.get("username"))
    print("  Email:     ", user.get("email", "N/A"))
    print("  Phone:     ", user.get("phone", "N/A"))
    print("  Suspended: ", user.get("suspended", False))
    print()


def prompt_confirmation():
    """Prompt user to confirm the selected user.

    Returns:
        bool: True if confirmed, False otherwise.
    """
    while True:
        response = input("Is this the correct user? [y/N]: ").strip().lower()
        if response in ('y', 'yes'):
            return True
        elif response in ('n', 'no', ''):
            return False
        else:
            print("Please enter 'y' or 'n'")


def prompt_new_password():
    """Prompt for new password twice and verify they match.

    Returns:
        str: The new password.

    Raises:
        SystemExit: If passwords don't match or input is cancelled.
    """
    try:
        password1 = getpass.getpass("Enter new password: ")
        if not password1:
            print("Error: Password cannot be empty.")
            sys.exit(1)
        password2 = getpass.getpass("Confirm new password: ")
        if password1 != password2:
            print("Error: Passwords do not match.")
            sys.exit(1)
        return password1
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled.")
        sys.exit(1)


def hash_password(password):
    """Hash password using argon2.

    Args:
        password (str): Plain text password.

    Returns:
        str: Argon2 hashed password.
    """
    return argon2.PasswordHasher().hash(password)


def update_password(db, user_id, password_hash):
    """Update the user's password in the database.

    Args:
        db (pymongo.database.Database): MongoDB database handle.
        user_id: User's MongoDB _id.
        password_hash (str): Argon2 hashed password.

    Returns:
        bool: True if update was successful.
    """
    collection = db["c"]
    result = collection.update_one(
        {"_id": user_id},
        {"$set": {"__password": password_hash}}
    )
    return result.modified_count > 0


def main():
    """Main entry point for the password reset script."""
    parser = argparse.ArgumentParser(
        description="Reset a user's password in SeaCat Auth."
    )
    parser.add_argument(
        '-c', '--config',
        help='Path to config file',
        default='/conf/seacatauth.conf'
    )
    args = parser.parse_args()

    # Load MongoDB configuration
    try:
        mongodb_uri, mongodb_db = load_mongodb_config(args.config)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Prompt for username
    try:
        username = input("Enter username to reset password for: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled.")
        sys.exit(1)

    if not username:
        print("Error: Username cannot be empty.")
        sys.exit(1)

    # Connect to database and find user
    with mongodb_database(mongodb_uri, mongodb_db) as db:
        user = find_user(db, username)

        if user is None:
            print(f"Error: User '{username}' not found.")
            sys.exit(1)

        # Display user info and confirm
        display_user_info(user)

        if not prompt_confirmation():
            print("Operation cancelled.")
            sys.exit(0)

        # Prompt for new password
        new_password = prompt_new_password()

        # Hash the password
        password_hash = hash_password(new_password)

        # Update the database
        if update_password(db, user["_id"], password_hash):
            print(f"\nPassword successfully updated for user '{user.get('username')}'.")
        else:
            print("\nError: Failed to update password (user may not exist).")
            sys.exit(1)


if __name__ == "__main__":
    main()
