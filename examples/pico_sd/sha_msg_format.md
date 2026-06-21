# SHA-256 Message Format

SHA-256 processes input data through a structured format to ensure the integrity and uniqueness of the resulting hash. Below are the key steps involved in formatting a message for SHA-256 hashing.
Steps in SHA-256 Message Formatting

    Padding the Message
        The original message is padded with a '1' bit followed by '0' bits.
        Padding continues until the length of the message is 64 bits shy of a multiple of 512 bits.

    Appending Length
        After padding, the length of the original message (in bits) is appended as a 64-bit integer.
        This ensures that the total length of the padded message is a multiple of 512 bits.

    Dividing into Blocks
        The padded message is divided into blocks of 512 bits each.
        Each block will be processed individually during the hashing process.

