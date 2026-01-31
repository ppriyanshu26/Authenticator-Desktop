import socket
import json
import threading
import time
import queue
import aes

class SyncConnection:
    SYNC_PORT = 34568
    current_server = None
    listening_thread = None
    
    @staticmethod
    def stop_listening():
        if SyncConnection.current_server:
            try:
                SyncConnection.currServer.close()
            except:
                pass
        SyncConnection.currServer = None
    
    @staticmethod
    def send_password_hash_and_sync(device_ip, password_hash, master_password, local_credentials):
        try:
            print(f'[SYNC_CONN] Connecting to {device_ip}:{SyncConnection.SYNC_PORT}')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((device_ip, SyncConnection.SYNC_PORT))
            
            message = json.dumps({
                'type': 'PASSWORD_HASH',
                'hash': password_hash,
            })
            print(f'[SYNC_CONN] Sending: {message}')
            sock.send(message.encode('utf-8'))
            
            response = sock.recv(1024)
            remote_message = json.loads(response.decode('utf-8'))
            print(f'[SYNC_CONN] Received: {remote_message}')
            
            if remote_message.get('hash') != password_hash:
                sock.close()
                return {'success': False, 'reason': 'password_mismatch'}
            
            request_message = json.dumps({'type': 'REQUEST_DATA'})
            sock.send(request_message.encode('utf-8'))
            
            data_response = sock.recv(8192)
            data_message = json.loads(data_response.decode('utf-8'))
            print(f'[SYNC_CONN] Received data response type: {data_message.get("type")}')
            
            if data_message.get('type') != 'DATA_RESPONSE':
                sock.close()
                return {'success': False, 'reason': 'invalid_response'}
            
            encrypted_remote_data = data_message.get('encrypted_data')
            try:
                crypto = aes.Crypto(master_password)
                decrypted_remote_data = crypto.decrypt_aes(encrypted_remote_data)
                remote_credentials = json.loads(decrypted_remote_data)
            except Exception as e:
                print(f'[SYNC_CONN] Decryption error: {e}')
                sock.close()
                return {'success': False, 'reason': 'decryption_error'}
            
            merged_credentials = SyncConnection.mergeCreds(local_credentials, remote_credentials)
            
            merged_json = json.dumps(merged_credentials)
            try:
                crypto = aes.Crypto(master_password)
                encrypted_merged_data = crypto.encrypt_aes(merged_json)
            except Exception as e:
                print(f'[SYNC_CONN] Encryption error: {e}')
                sock.close()
                return {'success': False, 'reason': 'encryption_error'}
            
            merged_message = json.dumps({
                'type': 'MERGED_DATA',
                'encrypted_data': encrypted_merged_data,
            })
            sock.send(merged_message.encode('utf-8'))
            sock.close()
            
            print('[SYNC_CONN] PASSWORD MATCH AND CREDENTIALS SYNCED!')
            return {'success': True, 'merged_credentials': merged_credentials}
        except Exception as e:
            print(f'[SYNC_CONN] Error: {e}')
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
                print(f'[SYNC_CONN] Listening on port {SyncConnection.SYNC_PORT}')
                
                while SyncConnection.currServer is server:
                    try:
                        server.settimeout(1)
                        client_sock, client_addr = server.accept()
                        print(f'[SYNC_CONN] Client connected from {client_addr}')
                        
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
                print(f'[SYNC_CONN] Server error: {e}')
            finally:
                try:
                    server.close()
                except:
                    pass
        
        thread = threading.Thread(target=listen_thread, daemon=True)
        SyncConnection.listeningThreadhread = thread
        thread.start()
    
    @staticmethod
    def handle_sync_connection(client_sock, password_hash, master_password, local_credentials, on_complete_callback, gui_queue=None):
        try:
            password_matched = False
            
            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                message = json.loads(data.decode('utf-8'))
                message_type = message.get('type')
                print(f'[SYNC_CONN] Received: {message_type}')
                
                if message_type == 'PASSWORD_HASH':
                    remote_hash = message.get('hash')
                    password_matched = remote_hash == password_hash
                    
                    response = json.dumps({
                        'type': 'PASSWORD_HASH_RESPONSE',
                        'hash': password_hash,
                        'match': password_matched,
                    })
                    client_sock.send(response.encode('utf-8'))
                    
                elif message_type == 'REQUEST_DATA' and password_matched:
                    try:
                        credentials_json = json.dumps(local_credentials)
                        crypto = aes.Crypto(master_password)
                        encrypted_data = crypto.encrypt_aes(credentials_json)
                        
                        response = json.dumps({
                            'type': 'DATA_RESPONSE',
                            'encrypted_data': encrypted_data,
                        })
                        client_sock.send(response.encode('utf-8'))
                    except Exception as e:
                        print(f'[SYNC_CONN] Encryption error: {e}')
                        client_sock.close()
                        break
                
                elif message_type == 'MERGED_DATA' and password_matched:
                    try:
                        encrypted_merged_data = message.get('encrypted_data')
                        crypto = aes.Crypto(master_password)
                        decrypted_merged_data = crypto.decrypt_aes(encrypted_merged_data)
                        merged_credentials = json.loads(decrypted_merged_data)
                        
                        print('[SYNC_CONN] RECEIVED MERGED DATA - SYNC COMPLETE!')
                        
                        if gui_queue:
                            gui_queue.put((True, merged_credentials))
                        else:
                            on_complete_callback(True, merged_credentials)
                        
                        client_sock.close()
                        break
                    except Exception as e:
                        print(f'[SYNC_CONN] Decryption error: {e}')
                        client_sock.close()
                        break
        except Exception as e:
            print(f'[SYNC_CONN] Connection error: {e}')
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

