#!/usr/bin/env python

'''
tls_psk_functions.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Hash import HMAC, SHA256, SHA384
from Crypto.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions

PSK_KE_MODE = 0
PSK_DHE_KE_MODE = 1
PRESHARED_KEY_TYPE = 41
EARLY_DATA_TYPE = 42
PRESHARED_KEY_TYPE = 45

class DecryptError(Error):
    pass

class PSKFunctions:
    "This is the class for aspects of the handshake protocol"

    def __init__(self, csuites, extensions, psks, role):
        self.csuites = csuites
        self.extensions = extensions
        self.state = tls_constants.INIT_STATE
        self.role = role
        self.neg_group = None
        self.neg_version = None
        self.remote_hs_traffic_secret = None
        self.local_hs_traffic_secret = None
        self.transcript = "".encode()
        self.psks = PSKFunctions
        self.csuite = None


    def attach_handshake_header(self, msg_type, msg):
        len_msg = len(msg).to_bytes(3, 'big')
        hs_msg_type = msg_type.to_bytes(1, 'big')
        return hs_msg_type + len_msg + msg


    def process_handshake_header(self, msg_type, msg):
        curr_pos = 0
        curr_msg_type = msg[curr_pos]
        if (curr_msg_type != msg_type):
            raise InvalidMessageStructureError
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        ptxt_msg = msg[curr_pos:]
        if (msg_len != len(ptxt_msg)):
            raise InvalidMessageStructureError
        return ptxt_msg


    def tls_13_server_new_session_ticket(self, server_static_enc_key, resumption_secret):
        ticket_lifetime = (604800).to_bytes(4, 'big')
        ticket_age_add = get_random_bytes(4)
        ticket_nonce_len = (8).to_bytes(1, 'big')
        ticket_nonce = get_random_bytes(8)        
        #PSK calculation
        suite = tls_constants.TLS_CHACHA20_POLY1305_SHA256
        
        hkdf = tls_crypto.HKDF(self.csuite)
        hkdf_lbl = tls_crypto.tls_hkdf_label( 'resumption'.encode(), ticket_nonce, hkdf.hash_length)
        PSK = hkdf.tls_hkdf_expand(resumption_secret, hkdf_lbl, hkdf.hash_length)
    
        plaintext = PSK + ticket_age_add + ticket_lifetime + self.csuite.to_bytes(2, 'big')
        nonce = get_random_bytes(8)
        
        #ctxt = tls_crypto.tls_aead_encrypt(suite, server_static_enc_key, nonce, plaintext)
        cipher = ChaCha20_Poly1305.new(key=server_static_enc_key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        ctxt = ciphertext + tag
        
        ticket = nonce + ctxt

        ticket_len = (len(ticket)).to_bytes(2, 'big')   
        ext_len =(1).to_bytes(2,'big')
        ext_type = (tls_constants.EARLY_DATA_TYPE).to_bytes(1,'big') 
        early_data = (4096).to_bytes(4, 'big')
        #print(int.from_bytes(early_data, 'big'))
        session_ticket = ticket_lifetime + ticket_age_add + ticket_nonce_len + ticket_nonce + ticket_len + ticket + ext_len + ext_type + early_data
        return self.attach_handshake_header(tls_constants.NEWST_TYPE, session_ticket)
        


    def tls_13_client_parse_new_session_ticket(self, resumption_secret, nst_msg):
        nst = self.process_handshake_header(tls_constants.NEWST_TYPE, nst_msg)
        #print("zapravo ", len(nst), 'sa header', len(nst_msg))
        ticket_lifetime = int.from_bytes(nst[:4] , 'big')
        ticket_age_add = int.from_bytes(nst[4:8], 'big')
        ticket_nonce_len = nst[8:9]
        ticket_nonce = nst[9:17]
        ticket_len = int.from_bytes(nst[17:19] , 'big')
        ticket = nst[19:19+ticket_len]
        j = 19+ticket_len
        ext_len = nst[j:j+2]
        j = j+2
        ext_type = nst[j:j+1]
        j = j+1
        #print('j je ', j)
        early_data = int.from_bytes(nst[j:] , 'big')
        #early_data =int.from_bytes(nst[-4:] , 'big')
        #print(early_data)
        #processing ticket
        nonce = ticket[:8]
        ctxt = ticket[8:]
        
        hkdf = tls_crypto.HKDF(self.csuite)
        hkdf_lbl = tls_crypto.tls_hkdf_label( 'resumption'.encode(), ticket_nonce, hkdf.hash_length)
        PSK = hkdf.tls_hkdf_expand(resumption_secret, hkdf_lbl, hkdf.hash_length)
        
        es = tls_crypto.tls_extract_secret(self.csuite, PSK, None)
        bind_k = tls_crypto.tls_derive_secret(self.csuite, es, "res binder".encode(), "".encode())
        
        psk_dict = {"PSK" : PSK, "lifetime" : ticket_lifetime, "lifetime_add" : ticket_age_add , "ticket" : ticket, "max_data" : early_data, "binder key" : bind_k , "csuite" : self.csuite}
        return psk_dict
        #plaintext = tls_crypto.tls_aead_decrypt(self.csuite, server_static_enc_key, nonce, ctxt)

    def tls_13_client_prep_psk_mode_extension(self, modes):
        ext = (tls_constants.PSK_KEX_MODE_TYPE).to_bytes(2,'big')
        leng = len(modes)
        #print(type(leng))
        ext = ext + (leng).to_bytes(1,'big')
        for i in modes:
                #print(type(i))
                ext = ext + i.to_bytes(1,'big')
        #print(ext)
        return ext

    def tls_13_client_prep_psk_extension(self, PSKS, ticket_age, transcript):
        ext_type = (tls_constants.PSK_TYPE).to_bytes(2,'big')
        
        ############     CALCULATE IDENTITIES     ##############
        
        identities = b''
        for i in range(len(PSKS)):       
                if ticket_age[i] <= 1000 * PSKS[i]['lifetime'] :               
                        psk_identity = b''
                        identity = PSKS[i]['ticket']
                        identity_len = len(identity).to_bytes(2,'big') #encode no of bytes
                        obf_ticket_age = PSKS[i]['lifetime_add'] + ticket_age[i]
                        obf_ticket_age = (obf_ticket_age % (2 ** 32)).to_bytes(4,'big')
                        identities = identities + identity_len + identity + obf_ticket_age
        identities_len = len(identities).to_bytes(2,'big')
        
        
        ############     CALCULATE EXPECTED EXT LEN     ##############
        
        #calculate the expected binder_len 
        exp_binder_len = 0
        for i in range(len(PSKS)):       
                #binders need to correspont to valid tickets
                if ticket_age[i] <= 1000 * PSKS[i]['lifetime'] :               
                        
                        #decide which hash is used to implement HMAC and hence also determines the output size of HMAC
                        if (PSKS[i]['csuite'] == tls_constants.TLS_AES_128_GCM_SHA256) or (PSKS[i]['csuite'] == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
                                hash=SHA256.new()
                        if (PSKS[i]['csuite'] == tls_constants.TLS_AES_256_GCM_SHA384):
                                hash=SHA384.new()
                        #add 1 byte for the length encoding of the binder itself
                        exp_binder_len = exp_binder_len + hash.digest_size + 1
        
        binders_len = (exp_binder_len).to_bytes(2,'big')    
        #total len = length of identities encoding + length of identities + length of binder encodings + binders length 
        ext_len = (exp_binder_len + len(identities) + 4).to_bytes(2,'big') #length encoding of entire extension data
        
       
        ############     CALCULATE BINDERS     ##############
        
        binders = b''
        for i in range(len(PSKS)):       
                #binders need to correspont to valid tickets
                if ticket_age[i] <= 1000 * PSKS[i]['lifetime'] :            
                        binder = b''   
                        #hash the concatination of the transcrcipt + PreSharedKeyExt.identities
                        context = transcript + ext_type + ext_len + identities_len + identities #+ binders_len
                        transcript_hash = tls_crypto.tls_transcript_hash(PSKS[i]['csuite'], context)
                        tag = tls_crypto.tls_finished_mac(PSKS[i]['csuite'], PSKS[i]['binder key'], transcript_hash)
                        #tag length encoding
                        if (PSKS[i]['csuite'] == tls_constants.TLS_AES_128_GCM_SHA256) or (PSKS[i]['csuite'] == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
                                hash=SHA256.new()
                                bind_len = (hash.digest_size).to_bytes(1,'big')
                        if (PSKS[i]['csuite'] == tls_constants.TLS_AES_256_GCM_SHA384):
                                hash=SHA384.new()
                                bind_len = (hash.digest_size).to_bytes(1,'big')
                        binder = bind_len + tag
                        binders = binders + binder
        
        ########## CREATE FINAL EXTENSION ###########
        
        ext = ext_type + ext_len + identities_len + identities + binders_len + binders
        return ext
        
        

    def tls_13_server_parse_psk_extension(self, server_static_enc_key, psk_extension, transcript):
        ext_type = psk_extension[:2]
        ext_len = int.from_bytes(psk_extension[2:4], 'big')
        ext = psk_extension[4:4+ext_len]
        identities_len = int.from_bytes(ext[:2], 'big')
        identities = ext[2:2+identities_len]
        binders_len = int.from_bytes(ext[2+identities_len:4+identities_len],'big')
        binders = ext[4+identities_len:]
        
        ######  FIND FIRST VALID PSK + BINDER PAIR ##########
        ###### VALID IFF CIPHER == SELF.CSIPHER , ticket_age <= ticket_lifetime , ticket dec and valid, binder valid
        curr_ext_pos = 0
        curr_bind_pos = 0
        index = 0
        while (curr_ext_pos < identities_len):
                #start = curr_ext_pos
                id_len = int.from_bytes(identities[curr_ext_pos:curr_ext_pos+2], 'big')
                curr_ext_pos = curr_ext_pos + 2
                ticket = identities[curr_ext_pos:curr_ext_pos+id_len]
                curr_ext_pos = curr_ext_pos + id_len
                #end = curr_ext_pos + 4
                #identity = identities[start:end]
                obf_ticket_age = int.from_bytes(identities[curr_ext_pos:curr_ext_pos+4], 'big')
                
                nonce = ticket[:8]
                ciphertext = ticket[8:]
                cipher = ChaCha20_Poly1305.new(key=server_static_enc_key, nonce=nonce)
                aead_ctxt_len = len(ciphertext)
                mac_len = tls_constants.MAC_LEN[tls_constants.TLS_CHACHA20_POLY1305_SHA256]
                ctxt_len = aead_ctxt_len - mac_len
                ctxt = ciphertext[:ctxt_len]
                tag = ciphertext[ctxt_len:]
                try:
                        plaintext = cipher.decrypt_and_verify(ctxt, tag)
                        psk = plaintext[:len(plaintext)-10]
                        ticket_add_age_bytes = plaintext[len(psk):len(psk)+4]
                        add_age = int.from_bytes(ticket_add_age_bytes, 'big') 
                        ticket_lifetime_bytes = plaintext[len(psk)+4:len(psk)+8]
                        lifetime = int.from_bytes(ticket_lifetime_bytes, 'big')
                        suite = int.from_bytes(plaintext[len(psk)+8:len(psk)+10], 'big')
                        binder_len = int.from_bytes(binders[curr_bind_pos: curr_bind_pos + 1], 'big')

                        if (obf_ticket_age - add_age) % (2 ** 32) > 1000 * lifetime:
                                curr_ext_pos = curr_ext_pos + 4 #move on to the next identifier
                                curr_bind_pos = curr_bind_pos + binder_len + 1
                                index = index + 1
                                print('here')
                                continue
                                
                        if suite != self.csuite:
                                curr_ext_pos = curr_ext_pos + 4 #move on to the next identifier
                                curr_bind_pos = curr_bind_pos + binder_len + 1
                                index = index + 1
                                print('here2')
                                continue 

                        #if curr_bind_pos > binders_len:
                        #        print('here3')
                        #        break
                        
                        tag = binders[curr_bind_pos + 1 : curr_bind_pos + binder_len + 1]
                        es = tls_crypto.tls_extract_secret(suite, psk, None)
                        bind_k = tls_crypto.tls_derive_secret(suite, es, "res binder".encode(), "".encode())
                        context = transcript + ext_type + ext_len.to_bytes(2,'big') + identities_len.to_bytes(2,'big') + identities 
                        transcript_hash = tls_crypto.tls_transcript_hash(suite, context)
                        tls_crypto.tls_finished_mac_verify(suite, bind_k, transcript_hash, tag)
               
                        return psk, index

                except ValueError:
                       curr_ext_pos = curr_ext_pos + 4 #move on to the next identifier
                       curr_bind_pos = curr_bind_pos + binder_len + 1
                       index = index + 1
                       
                
        #here iff we failed
        return DecryptError()

    def tls_13_psk_key_schedule(self, psk_secret, dhe_secret, transcript_one, transcript_two, transcript_three, transcript_four):
        #early secret
        es = tls_crypto.tls_extract_secret(self.csuite, psk_secret, None)
        #binderkey
        bind_k = tls_crypto.tls_derive_secret(self.csuite, es, "res binder".encode(), "".encode()) 
        #client early traffic secret
        #client early key
        #client early iv 
        c_early_secret = tls_crypto.tls_derive_secret(self.csuite, es, "c e traffic".encode(), transcript_one) 
        ce_key, ce_iv = tls_crypto.tls_derive_key_iv(self.csuite, c_early_secret)
        
        #early exported master secret
        early_ms = tls_crypto.tls_derive_secret(self.csuite, es, "e exp master".encode(), transcript_one) 
        
        #derived early secret
        derived_early_s = tls_crypto.tls_derive_secret(self.csuite, es, "derived".encode(), "".encode()) 
        
        #hadnsahke secret
        hs = tls_crypto.tls_extract_secret(self.csuite, dhe_secret, derived_early_s)
        
        #client hadnshake traffic secret
        #client handshake key
        #client handshake iv
        ch_traff_s = tls_crypto.tls_derive_secret(self.csuite, hs, "c hs traffic".encode(), transcript_two) 
        ch_key, ch_iv = tls_crypto.tls_derive_key_iv(self.csuite, ch_traff_s)
        
        #server hadnshake traffic secret
        #server hanshake key
        #server hadnshake iv
        sh_traff_s = tls_crypto.tls_derive_secret(self.csuite, hs, "s hs traffic".encode(), transcript_two) 
        sh_key, sh_iv = tls_crypto.tls_derive_key_iv(self.csuite, sh_traff_s)
        
        #derived handshake secret
        derived_s = tls_crypto.tls_derive_secret(self.csuite, hs, "derived".encode(), "".encode()) 
        
        #master secret 
        hkdf = tls_crypto.HKDF(self.csuite)
        ms = tls_crypto.tls_extract_secret(self.csuite, (0).to_bytes(hkdf.hash_length , 'big'), derived_s)
        
        #client application traffic secret
        #client app key
        #client app iv
        capp_traff_s = tls_crypto.tls_derive_secret(self.csuite, ms, "c ap traffic".encode(), transcript_three) 
        capp_key, capp_iv = tls_crypto.tls_derive_key_iv(self.csuite, capp_traff_s) 
        
        #server app traffic secret
        #server app key
        #server app iv
        sapp_traff_s = tls_crypto.tls_derive_secret(self.csuite, ms, "s ap traffic".encode(), transcript_three) 
        sapp_key, sapp_iv = tls_crypto.tls_derive_key_iv(self.csuite, sapp_traff_s) 
        
        #exporter master secret
        exp_ms = tls_crypto.tls_derive_secret(self.csuite, ms, "exp master".encode(), transcript_three)
        
        #resumption master secret 
        res_ms = tls_crypto.tls_derive_secret(self.csuite, ms, "res master".encode(), transcript_four) 
        
        result = es , bind_k , c_early_secret , ce_key , ce_iv , early_ms , derived_early_s , hs , ch_traff_s , ch_key , ch_iv , sh_traff_s, sh_key , sh_iv , derived_s , ms , capp_traff_s , capp_key ,capp_iv , sapp_traff_s , sapp_key , sapp_iv , exp_ms , res_ms
        
        #print(type(result))
        return result
        
        
        
        
        
        
        
