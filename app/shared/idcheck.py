def char2int(input: str) -> int:
    if input.isdigit():
        return ord(input)-48
    elif input.isalpha():
        if input.isupper():
            return ord(input)-55
        else:
            return ord(input)-87
    else:
        raise Exception("Input is not alphanumeric")

def calculate_sum(input: str) -> int:
    value_string = ""
    int_sum = 0
    for char in input:
        value = char2int(char)
        value_string += str(value)
    for position, char in enumerate(value_string):
        digit = char2int(char)
        int_sum += digit*(2**(position%28))
    return int_sum

def checksum_int2char(checksum: int) -> str:
    if checksum < 10:
        return chr(checksum+48)
    elif checksum == 10:
        return "X"
    else:
        raise Exception("Checksum should be between 0-10 inclusive in integer value.")

def get_checksum(id_without_checksum: str) -> str:
    checksum_calculated = calculate_sum(id_without_checksum)%11
    return checksum_int2char(checksum_calculated)

def check_checksum(id: str) -> bool:
    id_without_checksum, checksum = id[:-1], id[-1]
    checksum_calculated = get_checksum(id_without_checksum)
    if checksum == checksum_calculated:
        return True
    return False

print(get_checksum("US3VJG34EU7D8U6JR6D"))
print(check_checksum("US3VJG34EU7D8U6JR6D8"))
print(get_checksum("US3PAA00003C4D58Y"))
print(check_checksum("US3VAA0000453C4D58Y9"))