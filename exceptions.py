class SHA1Error(Exception):
    def __init__(self, value = "SHA1 hash is not allowed"):
        super().__init__(value)

class ResponseNotAllowedError(Exception):
    def __init__(self, value):
        super().__init__(value)

class WrongIssuerError(Exception):
    def __init__(self, value = "Issuer in the database doesn't match the request hash data"):
        super().__init__(value)

class DBConnectionError(Exception):
    def __init__(self, value = "Failed to connect to MongoDB server"):
        super().__init__(value)

class NotImplementedError(Exception):
    def __init__(self, value):
        super().__init__(value)

class EntryNotFoundError(Exception):
    def __init__(self, id_type: str, value: str):
        super().__init__("Entry with " + id_type + " " + value + " not found in the database.")