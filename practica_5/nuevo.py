#!/usr/bin/env python3

from getpass import getpass
from base64 import b64encode
from SecureString import clearmem
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA512
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
import MySQLdb, sys, ast

def procesar_pacientes(archivo, key):
    """Procesa el archivo de pacientes y devuelve una lista de registros cifrados"""
    registros = []
    
    with open(archivo, 'r') as f:
        contenido = f.read()
        try:
            datos = ast.literal_eval(contenido)
        except:
            print("Error al parsear el archivo. Asegúrese que tiene el formato correcto.")
            sys.exit(1)
    
    for id_paciente, info in datos.items():
        name = info['name']
        diagnosis = bytes(info['diagnosis'], 'utf-8')
        treatment = bytes(info['treatment'], 'utf-8')
        
        # Generar nonces únicos
        diagnosis_nonce = get_random_bytes(8)
        treatment_nonce = get_random_bytes(8)
        
        # Cifrar los datos
        diag_aes = AES.new(key, AES.MODE_CTR, nonce=diagnosis_nonce)
        treat_aes = AES.new(key, AES.MODE_CTR, nonce=treatment_nonce)
        
        diagnosis_ciphertext = b64encode(diag_aes.encrypt(diagnosis))
        treatment_ciphertext = b64encode(treat_aes.encrypt(treatment))
        
        registros.append({
            'name': name,
            'diagnosis': diagnosis_ciphertext,
            'treatment': treatment_ciphertext,
            'diag_nonce': b64encode(diagnosis_nonce),
            'treat_nonce': b64encode(treatment_nonce)
        })
        
        # Limpiar variables sensibles
        clearmem(diagnosis)
        clearmem(treatment)
    
    return registros

def insertar_registros(registros, passwordSalt):
    """Inserta los registros en la base de datos"""
    mydb = None
    try:
        # Conexión directa (ajusta credenciales)
        mydb = MySQLdb.connect(
            host='localhost',
            user='root',      # Cambia por tu usuario
            password='',      # Cambia por tu contraseña
            database='hospital',
            port=3306
        )
        cursor = mydb.cursor()
        
        for registro in registros:
            cursor.execute(
                """INSERT INTO expediente 
                (nombre, diagnostico, tratamiento, passwordSalt, diag_nonce, treat_nonce) 
                VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    registro['name'],
                    registro['diagnosis'],
                    registro['treatment'],
                    passwordSalt,
                    registro['diag_nonce'],
                    registro['treat_nonce']
                )
            )
            print(f"Insertado: {registro['name']}")
        
        mydb.commit()
        print(f"\nTotal insertados: {len(registros)} registros")

    except Exception as err:
        print(f"\nError al insertar: {err}")
        sys.exit(1)
    finally:
        if mydb:
            cursor.close()
            mydb.close()
            print("Conexión cerrada")

def main():
    # Obtener contraseña para cifrar los datos
    password = getpass("Ingrese la contraseña de cifrado: ")
    
    # Generar salt para derivación de clave
    passwordSalt = get_random_bytes(16)
    
    # Derivar clave de cifrado
    key = PBKDF2(password, passwordSalt, 32, count=1000000, hmac_hash_module=SHA512)
    
    # Procesar archivo de pacientes
    registros = procesar_pacientes("diagnosticos_tratamientos.txt", key)
    
    # Codificar salt para almacenamiento
    passwordSalt = b64encode(passwordSalt)
    
    # Insertar registros en la base de datos
    insertar_registros(registros, passwordSalt)
    
    # Limpiar variables sensibles
    clearmem(key)
    clearmem(password)
    
    print("\nProceso completado exitosamente")

if __name__ == "__main__":
    main()
