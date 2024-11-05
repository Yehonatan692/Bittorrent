class TorentFile:
    __file_name: str
    __hash: str
    __user_name: str
    __size: int

    def __init__(self, file_name: str, hash: str, user_name: str, size: int):
        self.__file_name = file_name
        self.__hash = hash
        self.__user_name = user_name
        self.__size = size

    def get_file_name(self) -> str:
        return self.__file_name

    def get_hash(self) -> str:
        return self.__hash

    def get_user_name(self) -> str:
        return self.__user_name

    def get_size(self) -> int:
        return self.__size
