import socket
import json
import threading
import time
import queue
import aes

class SyncConnection:
    SYNC_PORT = 34568
    currServer = None
    listenThread = None
    
    @staticmethod
    def _recv_message(sock):
        buffer = b''
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                return None
            buffer += chunk
            if b'\n' in buffer:
                message_str, remainder = buffer.split(b'\n', 1)
                return message_str.decode('utf-8')
    
    @staticmethod
    def _send_message(sock, message_dict):
        message_str = json.dumps(message_dict)
        sock.send((message_str + '\n').encode('utf-8'))
    
    @staticmethod
    def stop_listening():
        if SyncConnection.currServer:
            try:
                SyncConnection.currServer.close()
            except:
                pass
        SyncConnection.currServer = None
    
    @staticmethod
    def send_password_hash_and_sync(device_ip, password_hash, master_password, local_credentials):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((device_ip, SyncConnection.SYNC_PORT))
            
            SyncConnection._send_message(sock, {
                'type': 'PASSWORD_HASH',
                'hash': password_hash,
            })
            response_str = SyncConnection._recv_message(sock)
            if not response_str:
                sock.close()
                return {'success': False, 'reason': 'no_response'}
            remote_message = json.loads(response_str)
            
            if remote_message.get('hash') != password_hash:
                sock.close()
                return {'success': False, 'reason': 'password_mismatch'}
            SyncConnection._send_message(sock, {'type': 'REQUEST_DATA'})
            
            data_response_str = SyncConnection._recv_message(sock)
            if not data_response_str:
                sock.close()
                return {'success': False, 'reason': 'no_response'}
            data_message = json.loads(data_response_str)
            
            if data_message.get('type') != 'DATA_RESPONSE':
                sock.close()
                return {'success': False, 'reason': 'invalid_response'}
            
            encrypted_remote_data = data_message.get('encrypted_data')
            try:
                crypto = aes.Crypto(master_password)
                decrypted_remote_data = crypto.decrypt_aes(encrypted_remote_data)
                remote_credentials = json.loads(decrypted_remote_data)
            except Exception as e:
                sock.close()
                return {'success': False, 'reason': 'decryption_error'}
            
            merged_credentials = SyncConnection.mergeCreds(local_credentials, remote_credentials)
            
            merged_json = json.dumps(merged_credentials)
            try:
                crypto = aes.Crypto(master_password)
                encrypted_merged_data = crypto.encrypt_aes(merged_json)
            except Exception as e:
                sock.close()
                return {'success': False, 'reason': 'encryption_error'}
            
            SyncConnection._send_message(sock, {
                'type': 'MERGED_DATA',
                'encrypted_data': encrypted_merged_data,
            })
            sock.close()
            
            return {'success': True, 'merged_credentials': merged_credentials}
        except Exception as e:
            return {'success': False, 'reason': 'connection_error', 'error': str(e)}
    
    @staticmethod
    def start_listening_for_sync(password_hash, master_password, local_credentials, on_complete_callback, gui_queue=None):
        SyncConnection.stop_listening()
        time.sleep(0.2)
        
        def listen_thread():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(('0.0.0.0', SyncConnection.SYNC_PORT))
                server.listen(1)
                SyncConnection.currServer = server
                
                while SyncConnection.currServer is server:
                    try:
                        server.settimeout(1)
                        client_sock, client_addr = server.accept()
                        
                        SyncConnection.handle_sync_connection(
                            client_sock,
                            password_hash,
                            master_password,
                            local_credentials,
                            on_complete_callback,
                            gui_queue,
                        )
                    except socket.timeout:
                        pass
                    except Exception as e:
                        if SyncConnection.currServer is server:
                            pass
            except Exception as e:
                pass
            finally:
                try:
                    server.close()
                except:
                    pass
        
        thread = threading.Thread(target=listen_thread, daemon=True)
        SyncConnection.listenThread = thread
        thread.start()
    
    @staticmethod
    def handle_sync_connection(client_sock, password_hash, master_password, local_credentials, on_complete_callback, gui_queue=None):
        try:
            password_matched = False
            
            while True:
                message_str = SyncConnection._recv_message(client_sock)
                if not message_str:
                    break
                
                message = json.loads(message_str)
                message_type = message.get('type')
                
                if message_type == 'PASSWORD_HASH':
                    remote_hash = message.get('hash')
                    password_matched = remote_hash == password_hash
                    
                    SyncConnection._send_message(client_sock, {
                        'type': 'PASSWORD_HASH_RESPONSE',
                        'hash': password_hash,
                        'match': password_matched,
                    })
                    
                elif message_type == 'REQUEST_DATA' and password_matched:
                    try:
                        credentials_json = json.dumps(local_credentials)
                        crypto = aes.Crypto(master_password)
                        encrypted_data = crypto.encrypt_aes(credentials_json)
                        
                        SyncConnection._send_message(client_sock, {
                            'type': 'DATA_RESPONSE',
                            'encrypted_data': encrypted_data,
                        })
                    except Exception as e:
                        client_sock.close()
                        break
                
                elif message_type == 'MERGED_DATA' and password_matched:
                    try:
                        encrypted_merged_data = message.get('encrypted_data')
                        crypto = aes.Crypto(master_password)
                        decrypted_merged_data = crypto.decrypt_aes(encrypted_merged_data)
                        merged_credentials = json.loads(decrypted_merged_data)
                        
                        if gui_queue:
                            gui_queue.put((True, merged_credentials))
                        else:
                            on_complete_callback(True, merged_credentials)
                        
                        client_sock.close()
                        break
                    except Exception as e:
                        client_sock.close()
                        break
        except Exception as e:
            pass
        finally:
            try:
                client_sock.close()
            except:
                pass
    
    @staticmethod
    def mergeCreds(local_creds, remote_creds):
        merged = {}
        for cred in local_creds:
            cred_id = cred.get('id')
            if cred_id:
                merged[cred_id] = cred.copy()
        for cred in remote_creds:
            cred_id = cred.get('id')
            if cred_id:
                merged[cred_id] = {
                    'id': cred_id,
                    'platform': cred.get('platform', ''),
                    'username': cred.get('username', ''),
                    'secretcode': cred.get('secretcode', ''),
                }
        merged_list = list(merged.values())
        merged_list.sort(key=lambda x: x.get('platform', '').lower())
        
        return merged_list

