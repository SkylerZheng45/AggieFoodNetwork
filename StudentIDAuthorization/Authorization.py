from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


class database_simulator:
    UIN = "123456789"
    student_name = ""
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key


class driver_simulator:
    signature= ""
    def __init__(self, public_key):
        self.public_key = public_key


def generate_keys():
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public = private.public_key()
    return private, public


def sign(message, private):
    message = bytes(str(message), 'utf-8')
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return sig


def verify(message, sig, public):
    message = bytes(str(message), 'utf-8')
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public_key.verify")
        return False


if __name__ == "__main__":
    # After clicking on "Authorize"
    # generate the private and public key
    private_key, public_key = generate_keys()

    # store the keys in the database
    database = database_simulator(private_key, public_key)

    # Authorization Link Sent to the TAMU Email Address
    input("Enter any key to authorize the action (Simulating Clicking on Link to authorize)")

    # In the server, use the private_key to create a signature
    student_info = database.UIN + " " + database.student_name
    signature = sign(student_info, private_key)

    # In the server, send the public key and signature to the driver
    driver = driver_simulator(public_key)
    driver.signature = signature

    # the driver verify the credentials
    if verify(student_info, signature, public_key):
        print("Successfully verified.")
    else:
        print("Nope, you're not the actual person.")


