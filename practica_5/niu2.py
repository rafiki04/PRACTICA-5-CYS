#!/usr/bin/env python3

from getpass import getpass
from base64 import b64encode, b64decode
from SecureString import clearmem
from Cryptodome.Protocol.KDF import scrypt
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
        
        # Cifrar los datos con AES-GCM
        try:
            # Cifrar diagnóstico
            diag_cipher = AES.new(key, AES.MODE_GCM)
            diagnosis_ciphertext, diag_tag = diag_cipher.encrypt_and_digest(diagnosis)
            
            # Cifrar tratamiento
            treat_cipher = AES.new(key, AES.MODE_GCM)
            treatment_ciphertext, treat_tag = treat_cipher.encrypt_and_digest(treatment)
            
            registros.append({
                'name': name,
                'diagnosis': b64encode(diagnosis_ciphertext),
                'treatment': b64encode(treatment_ciphertext),
                'diag_nonce': b64encode(diag_cipher.nonce),
                'treat_nonce': b64encode(treat_cipher.nonce),
                'diag_tag': b64encode(diag_tag),
                'treat_tag': b64encode(treat_tag)
            })
            
        except Exception as e:
            print(f"Error al cifrar datos para {name}: {str(e)}")
            continue
        
        finally:
            # Limpiar variables sensibles
            clearmem(diagnosis)
            clearmem(treatment)
            del diag_cipher, treat_cipher
    
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
            database='hospitalnuevo',
            port=3306
        )
        cursor = mydb.cursor()
        
        for registro in registros:
            cursor.execute(
                """INSERT INTO expediente 
                (nombre, diagnostico, tratamiento, passwordSalt, diag_nonce, treat_nonce, diag_tag, treat_tag) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    registro['name'],
                    registro['diagnosis'],
                    registro['treatment'],
                    passwordSalt,
                    registro['diag_nonce'],
                    registro['treat_nonce'],
                    registro['diag_tag'],
                    registro['treat_tag']
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

def recuperar_paciente():
    """Recupera y descifra la información de un paciente específico"""
    nombre_paciente = input("\nIngrese el nombre del paciente a buscar: ")
    password = getpass("Ingrese la contraseña de cifrado: ")
    password_bytes = password.encode('utf-8')
    
    mydb = None
    try:
        # Conexión a la base de datos
        mydb = MySQLdb.connect(
            host='localhost',
            user='root',
            password='',
            database='hospitalnuevo',
            port=3306
        )
        cursor = mydb.cursor()
        
        # Buscar al paciente
        cursor.execute(
            """SELECT diagnostico, tratamiento, passwordSalt, diag_nonce, treat_nonce, diag_tag, treat_tag 
            FROM expediente WHERE nombre = %s""",
            (nombre_paciente,)
        )
        
        resultado = cursor.fetchone()
        
        if not resultado:
            print(f"\nNo se encontró al paciente: {nombre_paciente}")
            return
        
        # Extraer datos cifrados
        (diagnostico_cifrado, tratamiento_cifrado, passwordSalt, 
         diag_nonce, treat_nonce, diag_tag, treat_tag) = resultado
        
        # Decodificar datos desde Base64
        salt = b64decode(passwordSalt)
        key = scrypt(
            password=password_bytes,
            salt=salt,
            key_len=32,
            N=2**20,
            r=8,
            p=1
        )
        
        # Descifrar diagnóstico
        diag_cipher = AES.new(
            key, 
            AES.MODE_GCM, 
            nonce=b64decode(diag_nonce)
        )
        diagnostico = diag_cipher.decrypt_and_verify(
            b64decode(diagnostico_cifrado),
            b64decode(diag_tag)
        ).decode('utf-8')
        
        # Descifrar tratamiento
        treat_cipher = AES.new(
            key, 
            AES.MODE_GCM, 
            nonce=b64decode(treat_nonce)
        )
        tratamiento = treat_cipher.decrypt_and_verify(
            b64decode(tratamiento_cifrado),
            b64decode(treat_tag)
        ).decode('utf-8')
        
        # Mostrar resultados
        print(f"\nInformación para {nombre_paciente}:")
        print(f"Diagnóstico: {diagnostico}")
        print(f"Tratamiento: {tratamiento}")
        
    except Exception as e:
        print(f"\nError al descifrar: {str(e)}")
        if "MAC check failed" in str(e):
            print("¡Contraseña incorrecta o datos corruptos!")
    
    finally:
        # Limpieza de seguridad
        if mydb:
            cursor.close()
            mydb.close()
        clearmem(key) if 'key' in locals() else None
        clearmem(password_bytes)
        clearmem(password)

def main():
    print("1. Cifrar e insertar nuevos registros")
    print("2. Buscar y descifrar información de paciente")
    opcion = input("Seleccione una opción (1/2): ")
    
    if opcion == '1':
        # Obtener contraseña para cifrar los datos
        password = getpass("Ingrese la contraseña de cifrado: ")
        password_bytes = password.encode('utf-8')
        
        try:
            # Generar salt para derivación de clave
            passwordSalt = get_random_bytes(16)
            
            # Derivar clave de cifrado usando scrypt
            key = scrypt(
                password=password_bytes,
                salt=passwordSalt,
                key_len=32,
                N=2**20,
                r=8,
                p=1
            )
            
            # Procesar archivo de pacientes
            registros = procesar_pacientes("diagnosticos_tratamientos.txt", key)
            
            # Codificar salt para almacenamiento
            passwordSalt = b64encode(passwordSalt)
            
            # Insertar registros en la base de datos
            insertar_registros(registros, passwordSalt)
            
            print("\nProceso completado exitosamente")
            
        except Exception as e:
            print(f"\nError en el proceso: {str(e)}")
            sys.exit(1)
            
        finally:
            # Limpiar variables sensibles
            clearmem(key) if 'key' in locals() else None
            clearmem(password_bytes)
            clearmem(password)
    
    elif opcion == '2':
        recuperar_paciente()
    
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
