import os
import asyncio
import aiohttp
import random
import string
import logging

# Configurar el registro del sistema
logging.basicConfig(level=logging.INFO)

async def obtener_token(url):
    # Generar un usuario y una clave aleatorios
    user = ''.join(random.choices(string.ascii_lowercase, k=5))
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

    async with aiohttp.ClientSession() as session:
        # Enviar la solicitud de login al servidor
        async with session.post(f"{url}/login", json={"user": user, "password": password}) as response:
            # Leer la respuesta del servidor
            response_text = await response.text()
            # Registrar la respuesta en el log del sistema
            logging.info(f"Respuesta del servidor (login): {response_text}")

            # Obtener el token JWT de la respuesta
            token = response_text
            return user, token

async def saludo(url):
    # Obtener el token JWT
    user, token = await obtener_token(url)
    if not token:
        logging.error("Error al obtener el token JWT")
        return

    nombre = user  # Puedes cambiar esto si deseas
    async with aiohttp.ClientSession() as session:
        # Enviar la solicitud de saludo al servidor, incluyendo el token JWT en la cabecera de autorización
        headers = {"Authorization": token}
        async with session.get(f"{url}/saludo?nombre={nombre}", headers=headers) as response:
            # Leer la respuesta del servidor
            response_text = await response.text()
            # Registrar la respuesta en el log del sistema
            logging.info(f"Respuesta del servidor (saludo): {response_text}")

async def main():
    # Obtener la URL del servidor desde la variable de entorno
    server_url = os.getenv("SERVER_URL")
    if not server_url:
        logging.error("La variable de entorno SERVER_URL no está configurada.")
        return

    # Realizar las solicitudes de login y saludo de forma asíncrona
    await asyncio.gather(
        saludo(server_url)
    )

if __name__ == "__main__":
    asyncio.run(main())