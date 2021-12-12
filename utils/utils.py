BASE_HEX = {"0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5",
            "6": "6", "7": "7", "8": "8", "9": "9",
            "a": "10", "b": "11", "c": "12", "d": "13", "e": "14", "f": "15",
            "10": "a", "11": "b", "12": "c", "13": "d", "14": "e", "15": "f"}


def convert_base_ten_to_b(number: int, base: int = 2) -> str:
    """
    Méthode qui me permet de convertir un nombre de base 10
    vers une base b (par défaut b = 2)

    :param number: le nombre en base 10 (ce nombre doit etre positif)
    :param base: la base vers laquelle convertir le nombre
    :return le nombre convertir en base donné en paramètre
    """
    if number < 0 or base <= 1:
        return ""
    if number == 0:
        return "0"
    remains = []
    dividende = number
    while dividende != 0:
        rest = dividende % base
        remains.append(BASE_HEX[str(rest)])
        dividende //= base
    remains.reverse()
    return "".join(remains)


def convert_base_b_to_ten(number: str, base: int = 2) -> int:
    """
    Méthode qui me permet de convertir un nombre
    d' une base b (par défaut b = 2) vers la base 10.

    :param number: le nombre à convertir en base 10
    :param base: la base à laquelle appartient le nombre à convertir
    :return le nombre en base 10
    :exception si la chaine de caractère est vide ou si la base est inférieur à 2
    """
    if not number:
        raise Exception("Invalid number")
    if base <= 1:
        raise Exception("The base must be greater than 1")
    lists = []
    for symbol in number:
        lists.append(symbol.lower())
    lists.reverse()
    valeur = 0
    for i in range(0, len(lists)):
        valeur += int(BASE_HEX[lists[i]]) * (base ** i)
    return valeur


def convert_base_b1_to_b2(number: str, base1: int, base2: int) -> str:
    """
    Fonction qui permet de convertir un nombre d' une certaine base vers une autre base
    :param number: nombre à convertir (en chaine de caractère)
    :param base1: la base de départ
    :param base2: la base d' arrivée
    :return: le nombre convertir (en chaine de caractère)
    """
    if base1 == base2:
        return number
    elif base1 == 10:
        return convert_base_ten_to_b(number=int(number), base=base2)
    elif base2 == 10:
        return str(convert_base_b_to_ten(number=number, base=base1))
    else:
        return convert_base_ten_to_b(number=convert_base_b_to_ten(number=number, base=base1), base=base2)


def count_one(number: str):
    if not number:
        return 0
    count = 0
    for bit in number:
        if int(bit) == 1:
            count += 1
    return count


def inverse_nombre(number):
    if number == 255:
        return 0
    if number == 0:
        return 255
    nb = convert_base_ten_to_b(number=number, base=2)
    ni = ""
    for bit in nb:
        if bit == "0":
            ni += "1"
        else:
            ni += "0"
    return convert_base_b_to_ten(number=ni, base=2)


def inverse_masque(masque):
    m = masque.split(".")
    s = []
    for elem in m:
        s.append(str(inverse_nombre(int(elem))))
    return ".".join(s)


def calcul_ttl_in_hour(ttl: int):
    """
    Fonction qui prend le temps sous forme de secondes
    et le retourne sous format heures-minutes-secondes

    :param ttl: le temps en secondes
    :return: le temps sous format heures-minutes-secondes
    """
    if ttl < 60:
        return str(ttl) + " secondes"
    mn = ttl // 60
    sc = ttl % 60
    if mn < 60:
        return str(mn) + " minutes " + str(sc) + " secondes"
    hr = mn // 60
    mn = mn % 60
    return str(hr) + " heurs " + str(mn) + " minutes " + str(sc) + " secondes"


TABLE_ASCII = {"00": " ", "01": " ", "02": " ", "03": " ", "04": " ", "05": " ", "06": " ", "07": " ",
               "08": " ", "09": " ", "0A": " ", "0B": " ", "0C": " ", "0D": " ", "0E": " ", "0F": " ",
               "10": " ", "11": " ", "12": " ", "13": " ", "14": " ", "15": " ", "16": " ", "17": " ",
               "18": " ", "19": " ", "1A": " ", "1B": " ", "1C": " ", "1D": " ", "1E": " ", "1F": " ",
               "20": " ", "21": "!", "22": '"', "23": "#", "24": "$", "25": "%", "26": "&", "27": "'",
               "28": "(", "29": ")", "2A": "*", "2B": "+", "2C": ",", "2D": "-", "2E": ".", "2F": "/",
               "30": "0", "31": "1", "32": "2", "33": "3", "34": "4", "35": "5", "36": "6", "37": "7",
               "38": "8", "39": "9", "3A": ":", "3B": ";", "3C": "<", "3D": "=", "3E": ">", "3F": "?",
               "40": "@", "41": "A", "42": "B", "43": "C", "44": "D", "45": "E", "46": "F", "47": "G",
               "48": "H", "49": "I", "4A": "J", "4B": "K", "4C": "L", "4D": "M", "4E": "N", "4F": "O",
               "50": "P", "51": "Q", "52": "R", "53": "S", "54": "T", "55": "U", "56": "V", "57": "W",
               "58": "X", "59": "Y", "5A": "Z", "5B": "[", "5C": "\\", "5D": "]", "5E": "^", "5F": "_",
               "60": "'", "61": "a", "62": "b", "63": "c", "64": "d", "65": "e", "66": "f", "67": "g",
               "68": "h", "69": "i", "6A": "j", "6B": "k", "6C": "l", "6D": "m", "6E": "n", "6F": "o",
               "70": "p", "71": "q", "72": "r", "73": "s", "74": "t", "75": "u", "76": "v", "77": "w",
               "78": "x", "79": "y", "7A": "z", "7B": "{", "7C": "|", "7D": "}", "7E": "˜", "7F": "_"}


def get_str_ascii(my_str=""):
    if not my_str:
        return ""
    result = ""
    for i in range(0, len(my_str)-1, 2):
        c = my_str[i:i+2]
        if c in TABLE_ASCII.keys():
            result += TABLE_ASCII[c]
    return result
