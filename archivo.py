import mysql.connector
import csv

CONFIG = {
    'host':     'localhost',
    'user':     'root',
    'password': '9123',
    'database': 'diana_db'
}

ID_PARTICIPANTE = 2  # <- cambia al ID real del P2

conn = mysql.connector.connect(**CONFIG)
cursor = conn.cursor()

cursor.execute("""
    SELECT r.orden, i.clave, i.nivel, i.b,
           r.es_correcta, r.theta_post, r.sem_post
    FROM respuestas r
    JOIN items i ON r.item_id = i.id
    JOIN sesiones_examen s ON r.sesion_id = s.id
    WHERE s.usuario_id = %s
    ORDER BY r.orden
""", (ID_PARTICIPANTE,))

filas = cursor.fetchall()

with open('p2_resultados.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['orden','clave','nivel','b','correcto','theta','sem'])
    writer.writerows(filas)

print(f"✅ Exportado: {len(filas)} filas → p2_resultados.csv")
cursor.close()
conn.close()