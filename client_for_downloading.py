import socket, ast, threading
import datetime, os
from tcp_by_size import recv_by_size, send_with_size

IP = "127.0.0.1"
PORT = 1111


def receive_file(sock, filename):
    """
    Receives a file from the server in chunks and saves it to the specified filename.

    Args:
     sock: The socket to receive the data from.
     filename: The name of the file to save.
    """
    chunk_count = 0
    # Receive the number of expected chunks
    num_chunks = recv_by_size(sock)
    num_chunks = num_chunks.decode().split('~')[1]
    num_chunks = int(num_chunks)
    if num_chunks == 0:
        print("Error receiving file: No data received")
        return
    try:
        file_name = filename.split('\\')[1]
        path ="e:\\torrent_files\\"+filename.split('\\')[0]
        os.makedirs(path)
        with open(path + "\\" + file_name, 'wb') as f:
            while chunk_count < num_chunks:
                # Receive the chunk data
                chunk = recv_by_size(sock)
                # Write the chunk data to the file
                f.write(chunk)
                chunk_count += 1
    except Exception as e:
        print(e)


def end_to_end_download_file(DFS_answer: str):
    DFS_fields = DFS_answer.split('~')
    file_size = int(DFS_fields[2])
    clients_to_download_from = ast.literal_eval(DFS_fields[1])
    sheerit = file_size % len(clients_to_download_from)
    file_chunk_size = (file_size - sheerit) / len(clients_to_download_from)
    threads = []
    i = 1
    for client in clients_to_download_from:
        ip = client[0]
        port = client[1]
        path = client[2]

        sock = socket.socket()
        sock.connect((ip, port))
        t = threading.Thread(target=download_from_client, args=(sock, i, path, file_chunk_size, sheerit, clients_to_download_from.index(client)))
        t.start()
        i += 1
        threads.append(t)


def download_from_client(sock, tid, path, chunk_size, sheerit, id):
    chunk_size =int(sheerit+chunk_size) if id == 0 else int(chunk_size)
    to_send = "GTF~" + path + "~" + str(int(id * chunk_size)) + "~" + str(chunk_size)
    send_with_size(sock, to_send.encode())
    file_name =os.path.basename(path).split('.')
    receive_file(sock,file_name[0]+"\\"+f"{id}."+file_name[1])


def main():
    end_to_end_download_file(r"DFS~[('127.0.0.1',1111,'e:\\beitar.png')]~4740889")
    '''
    cli_sock = socket.socket()
    cli_sock.connect((IP, PORT))
    to_send = "GTF~{file_name}"
    to_send = to_send.encode()
    send_with_size(cli_sock, to_send)
    receive_file(cli_sock, "e:\\Python\\beitar.png")    
    '''



if __name__ == '__main__':
    main()
