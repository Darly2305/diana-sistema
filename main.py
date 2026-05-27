"""
DIANA — Backend FastAPI
========================
Sistema de diagnóstico adaptativo para Código para Todos
Universidad Veracruzana

Instalar dependencias:
    pip install fastapi uvicorn mysql-connector-python bcrypt numpy

Ejecutar:
    uvicorn main:app --reload --port 8000

Endpoints:
    POST /registro          — Crear cuenta
    POST /login             — Autenticación
    POST /encuesta          — Guardar encuesta previa
    GET  /examen/estado     — Verificar si tiene sesión activa
    GET  /examen/siguiente  — Obtener siguiente ítem
    POST /examen/responder  — Enviar respuesta y actualizar θ
    GET  /examen/resultado  — Resultado final
    GET  /investigador      — Panel en tiempo real (solo Darly)
    GET  /investigador/{id} — Trayectoria de θ de un estudiante
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
import mysql.connector
import bcrypt
import numpy as np
import json
import hmac
import hashlib
import base64
from datetime import datetime, timedelta, timezone

app = FastAPI(title="DIANA API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*", "null"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)

# ================================================================
# CONFIGURACIÓN
# ================================================================
DB_CONFIG = {
    'host':     'localhost',
    'port':     3306,
    'user':     'root',
    'password': '9123',
    'database': 'diana_db'
}

# ================================================================
# JWT — Implementación manual sin dependencias externas
# ================================================================
JWT_SECRET  = "diana-uv-investigacion-2025-xk92"  # Cambia esto en producción
JWT_EXPIRY_HOURS = 8  # Token válido por 8 horas

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64url_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + '=' * padding)

def crear_jwt(usuario: str, nombre: str) -> str:
    """Genera un JWT firmado con HS256."""
    import json as _json
    header  = _b64url(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    exp     = int((datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)).timestamp())
    payload = _b64url(json.dumps({"sub": usuario, "nombre": nombre, "exp": exp}).encode())
    firma   = _b64url(hmac.new(
        JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
    ).digest())
    return f"{header}.{payload}.{firma}"

def verificar_jwt(token: str) -> dict:
    """Verifica JWT y retorna payload. Lanza HTTPException si es inválido."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Formato inválido")
        header, payload, firma = parts
        firma_esperada = _b64url(hmac.new(
            JWT_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256
        ).digest())
        if not hmac.compare_digest(firma, firma_esperada):
            raise ValueError("Firma inválida")
        data = json.loads(_b64url_decode(payload))
        if data.get('exp', 0) < datetime.now(timezone.utc).timestamp():
            raise ValueError("Token expirado")
        return data
    except ValueError as e:
        raise HTTPException(401, f"Token inválido: {e}")

def get_admin(authorization: str = Header(None)):
    """Dependencia FastAPI — verifica que el request venga de un admin autenticado."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Se requiere autenticación de administrador")
    token = authorization.replace("Bearer ", "")
    return verificar_jwt(token)

# ================================================================
# PARÁMETROS CAT
# ================================================================
THETA_GRID = np.linspace(-4, 4, 200)
PRIOR      = np.exp(-0.5 * THETA_GRID**2) / np.sqrt(2 * np.pi)

SEM_UMBRAL          = 0.35   # Criterio de precisión
DELTA_THETA_UMBRAL  = 0.05   # Criterio de estancamiento
PASOS_ESTANCAMIENTO = 5      # Cuántos pasos consecutivos sin cambio

# Theta inicial según nivel de experiencia declarada en encuesta
# nivel_experiencia:
#   0 = nunca ha programado             → principiante directo sin examen
#   1 = básico (variables, operadores)  → θ₀ = -1.2
#   2 = intermedio (ciclos, métodos)    → θ₀ = -0.3
#   3 = POO, colecciones, herencia      → θ₀ =  0.5
#   4 = avanzado (proyectos reales)     → θ₀ =  1.0
THETA_POR_EXPERIENCIA = {
    0: None,   # sin examen, principiante directo
    1: -1.2,
    2: -0.3,
    3:  0.5,
    4:  1.0,
}

# ================================================================
# BASE DE DATOS
# ================================================================
def get_db():
    conn = mysql.connector.connect(**DB_CONFIG)
    try:
        yield conn
    finally:
        conn.close()

def db_query(conn, sql, params=None, fetch='all'):
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, params or ())
    if fetch == 'all':
        result = cursor.fetchall()
    elif fetch == 'one':
        result = cursor.fetchone()
    else:
        result = cursor.lastrowid
    cursor.close()
    return result

def db_execute(conn, sql, params=None):
    cursor = conn.cursor()
    cursor.execute(sql, params or ())
    conn.commit()
    lid = cursor.lastrowid
    cursor.close()
    return lid

# ================================================================
# MODELOS
# ================================================================
class RegistroRequest(BaseModel):
    correo:    str
    password:  str
    nombre:    str
    apellido:  str
    semestre:  Optional[int] = None
    grupo:     Optional[str] = None

class LoginRequest(BaseModel):
    correo:   str
    password: str

class EncuestaRequest(BaseModel):
    usuario_id:          int
    ha_programado:       bool
    nivel_experiencia:   int    # 0-4 según escala de experiencia
    lenguajes_previos:   Optional[str] = None
    confianza_nivel:     Optional[int] = None

class AdminLoginRequest(BaseModel):
    usuario:    str
    password:   str

class RespuestaRequest(BaseModel):
    sesion_id:      int
    item_id:        int
    respuesta_dada: str

# --- Login administrador ---
@app.post("/admin/login")
def admin_login(req: AdminLoginRequest, conn=Depends(get_db)):
    admin = db_query(conn,
        "SELECT * FROM administradores WHERE usuario = %s",
        (req.usuario,), fetch='one'
    )
    if not admin:
        raise HTTPException(401, "Usuario o contraseña incorrectos")
    if not bcrypt.checkpw(req.password.encode(), admin['contrasena_hash'].encode()):
        raise HTTPException(401, "Usuario o contraseña incorrectos")

    token = crear_jwt(admin['usuario'], admin['nombre'])
    return {
        "ok":     True,
        "token":  token,
        "nombre": admin['nombre'],
        "expira_en_horas": JWT_EXPIRY_HOURS
    }

# --- Verificar token (el panel lo usa al cargar) ---
@app.get("/admin/verificar")
def admin_verificar(admin=Depends(get_admin)):
    return {"ok": True, "usuario": admin['sub'], "nombre": admin['nombre']}


    sesion_id:     int
    item_id:       int
    respuesta_dada: str

# ================================================================
# ALGORITMO IRT — Rasch (a=1.0)
# ================================================================
def p_2pl(theta, a, b):
    return 1.0 / (1.0 + np.exp(-a * (theta - b)))

def info_item(theta, a, b):
    p = p_2pl(theta, a, b)
    return (a**2) * p * (1 - p)

def estimar_eap(respuestas, items_respondidos):
    posterior = PRIOR.copy().astype(float)
    for resp, item in zip(respuestas, items_respondidos):
        p = p_2pl(THETA_GRID, item['a'], item['b'])
        posterior *= p if resp == 1 else (1 - p)
    area = np.trapezoid(posterior, THETA_GRID)
    if area == 0:
        return 0.0, 1.0
    posterior /= area
    theta_hat = np.trapezoid(THETA_GRID * posterior, THETA_GRID)
    varianza  = np.trapezoid((THETA_GRID - theta_hat)**2 * posterior, THETA_GRID)
    return float(theta_hat), float(np.sqrt(varianza))

def clasificar(theta):
    if theta < -0.5:  return 'principiante'
    if theta <= 1.0:  return 'intermedio'
    return 'avanzado'

def seleccionar_item(theta_hat, items_banco, ids_usados):
    mejor = None
    mejor_info = -np.inf
    for item in items_banco:
        if item['id'] in ids_usados:
            continue
        info = info_item(theta_hat, item['a'], item['b'])
        if info > mejor_info:
            mejor_info = info
            mejor = item
    return mejor

# ================================================================
# ENDPOINTS
# ================================================================

# --- Registro ---
@app.post("/registro")
def registro(req: RegistroRequest, conn=Depends(get_db)):
    existente = db_query(conn,
        "SELECT id FROM usuarios WHERE correo = %s",
        (req.correo,), fetch='one'
    )
    if existente:
        raise HTTPException(400, "El correo ya está registrado")

    hash_pw = bcrypt.hashpw(req.password.encode(), bcrypt.gensalt()).decode()
    uid = db_execute(conn,
        """INSERT INTO usuarios (correo, contrasena_hash, nombre, apellido, semestre, grupo)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (req.correo, hash_pw, req.nombre, req.apellido, req.semestre, req.grupo)
    )
    return {"ok": True, "usuario_id": uid, "nombre": req.nombre}

# --- Login ---
@app.post("/login")
def login(req: LoginRequest, conn=Depends(get_db)):
    usuario = db_query(conn,
        "SELECT id, contrasena_hash, nombre FROM usuarios WHERE correo = %s",
        (req.correo,), fetch='one'
    )
    if not usuario:
        raise HTTPException(401, "Correo o contraseña incorrectos")

    if not bcrypt.checkpw(req.password.encode(), usuario['contrasena_hash'].encode()):
        raise HTTPException(401, "Correo o contraseña incorrectos")

    # Verificar si ya tiene encuesta
    encuesta = db_query(conn,
        "SELECT id FROM encuesta_previa WHERE usuario_id = %s",
        (usuario['id'],), fetch='one'
    )

    # Verificar si tiene sesión de examen
    sesion = db_query(conn,
        "SELECT id, estado, nivel_resultado FROM sesiones_examen WHERE usuario_id = %s",
        (usuario['id'],), fetch='one'
    )

    return {
        "ok": True,
        "usuario_id": usuario['id'],
        "nombre": usuario['nombre'],
        "tiene_encuesta": encuesta is not None,
        "tiene_sesion": sesion is not None,
        "estado_sesion": sesion['estado'] if sesion else None,
        "nivel_resultado": sesion['nivel_resultado'] if sesion else None
    }

# --- Encuesta previa ---
@app.post("/encuesta")
def guardar_encuesta(req: EncuestaRequest, conn=Depends(get_db)):
    # Verificar rango válido de nivel_experiencia
    if req.nivel_experiencia not in THETA_POR_EXPERIENCIA:
        raise HTTPException(400, "nivel_experiencia debe ser 0, 1, 2, 3 o 4")

    # Verificar si ya existe encuesta
    existente = db_query(conn,
        "SELECT id FROM encuesta_previa WHERE usuario_id = %s",
        (req.usuario_id,), fetch='one'
    )
    if existente:
        raise HTTPException(400, "La encuesta ya fue respondida")

    # Determinar theta inicial
    theta_ini = THETA_POR_EXPERIENCIA[req.nivel_experiencia]
    examen_requerido = theta_ini is not None

    # Si nunca ha programado → principiante directo
    if not examen_requerido:
        theta_ini = -2.0

    # Guardar encuesta
    db_execute(conn,
        """INSERT INTO encuesta_previa
           (usuario_id, ha_programado, nivel_experiencia, theta_inicial,
            lenguajes_previos, confianza_nivel)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (req.usuario_id, req.ha_programado, req.nivel_experiencia,
         theta_ini, req.lenguajes_previos, req.confianza_nivel)
    )

    if not examen_requerido:
        # Crear sesión completada sin examen
        db_execute(conn,
            """INSERT INTO sesiones_examen
               (usuario_id, estado, theta_actual, theta_inicial,
                nivel_resultado, theta_final, sem_final,
                iniciado_at, completado_at)
               VALUES (%s, 'saltado', %s, %s, 'principiante', %s, 1.0, NOW(), NOW())""",
            (req.usuario_id, theta_ini, theta_ini, theta_ini)
        )
        return {
            "ok": True,
            "examen_requerido": False,
            "nivel_asignado": "principiante",
            "theta_inicial": theta_ini,
            "mensaje": "Clasificado como principiante. Nunca ha programado."
        }

    # Crear sesión pendiente con theta inicial informado
    db_execute(conn,
        """INSERT INTO sesiones_examen
           (usuario_id, estado, theta_actual, sem_actual, theta_inicial)
           VALUES (%s, 'pendiente', %s, 1.0, %s)""",
        (req.usuario_id, theta_ini, theta_ini)
    )

    nivel_esperado = clasificar(theta_ini)

    return {
        "ok": True,
        "examen_requerido": True,
        "theta_inicial": theta_ini,
        "nivel_inicial_estimado": nivel_esperado,
        "mensaje": "Encuesta guardada. El examen comenzará desde tu nivel declarado."
    }

# --- Estado actual del examen ---
@app.get("/examen/estado/{usuario_id}")
def estado_examen(usuario_id: int, conn=Depends(get_db)):
    sesion = db_query(conn,
        "SELECT * FROM sesiones_examen WHERE usuario_id = %s",
        (usuario_id,), fetch='one'
    )
    if not sesion:
        raise HTTPException(404, "No se encontró sesión para este usuario")

    return {
        "sesion_id": sesion['id'],
        "estado": sesion['estado'],
        "theta_actual": sesion['theta_actual'],
        "sem_actual": sesion['sem_actual'],
        "n_items": sesion['n_items_respondidos'],
        "nivel_resultado": sesion['nivel_resultado']
    }

# --- Siguiente ítem del CAT ---
@app.get("/examen/siguiente/{sesion_id}")
def siguiente_item(sesion_id: int, conn=Depends(get_db)):
    sesion = db_query(conn,
        "SELECT * FROM sesiones_examen WHERE id = %s",
        (sesion_id,), fetch='one'
    )
    if not sesion:
        raise HTTPException(404, "Sesión no encontrada")
    if sesion['estado'] == 'completado':
        raise HTTPException(400, "El examen ya está completado")
    if sesion['estado'] == 'saltado':
        raise HTTPException(400, "Este usuario fue clasificado por encuesta")

    # Marcar como en progreso si es la primera pregunta
    if sesion['estado'] == 'pendiente':
        db_execute(conn,
            "UPDATE sesiones_examen SET estado='en_progreso', iniciado_at=NOW() WHERE id=%s",
            (sesion_id,)
        )

    # IDs ya usados
    usados = db_query(conn,
        "SELECT item_id FROM respuestas WHERE sesion_id = %s",
        (sesion_id,)
    )
    ids_usados = {r['item_id'] for r in usados}

    # Cargar banco completo (solo activos)
    banco = db_query(conn,
        "SELECT id, clave, enunciado, respuesta_correcta, opcion_b, opcion_c, opcion_d, b, a FROM items WHERE activo=1"
    )

    if not banco:
        raise HTTPException(500, "El banco de ítems está vacío")

    # Seleccionar ítem con máxima información
    theta_actual = float(sesion['theta_actual'])
    item = seleccionar_item(theta_actual, banco, ids_usados)

    if not item:
        # No hay más ítems — forzar cierre
        nivel = clasificar(theta_actual)
        db_execute(conn,
            """UPDATE sesiones_examen SET
               estado='completado', nivel_resultado=%s, theta_final=%s,
               sem_final=%s, completado_at=NOW()
               WHERE id=%s""",
            (nivel, theta_actual, sesion['sem_actual'], sesion_id)
        )
        return {"examen_completado": True, "nivel": nivel}

    # Mezclar opciones aleatoriamente
    import random
    opciones = [
        item['respuesta_correcta'],
        item['opcion_b'],
        item['opcion_c'],
        item['opcion_d']
    ]
    random.shuffle(opciones)

    return {
        "examen_completado": False,
        "item_id": item['id'],
        "clave": item['clave'],
        "enunciado": item['enunciado'],
        "opciones": opciones,
        "paso_actual": len(ids_usados) + 1
    }

# --- Enviar respuesta y actualizar θ ---
@app.post("/examen/responder")
def responder(req: RespuestaRequest, conn=Depends(get_db)):
    sesion = db_query(conn,
        "SELECT * FROM sesiones_examen WHERE id = %s",
        (req.sesion_id,), fetch='one'
    )
    if not sesion:
        raise HTTPException(404, "Sesión no encontrada")
    if sesion['estado'] == 'completado':
        raise HTTPException(400, "El examen ya está completado")

    item = db_query(conn,
        "SELECT * FROM items WHERE id = %s",
        (req.item_id,), fetch='one'
    )
    if not item:
        raise HTTPException(404, "Ítem no encontrado")

    es_correcta = int(req.respuesta_dada.strip() == item['respuesta_correcta'].strip())

    # Reconstruir historial completo para EAP
    historial = db_query(conn,
        """SELECT r.es_correcta, i.a, i.b
           FROM respuestas r JOIN items i ON r.item_id = i.id
           WHERE r.sesion_id = %s ORDER BY r.orden""",
        (req.sesion_id,)
    )

    respuestas_hist  = [h['es_correcta'] for h in historial] + [es_correcta]
    items_hist       = [{'a': h['a'], 'b': h['b']} for h in historial] + \
                       [{'a': item['a'], 'b': item['b']}]

    theta_nuevo, sem_nuevo = estimar_eap(respuestas_hist, items_hist)
    theta_anterior = float(sesion['theta_actual'])
    delta_theta    = abs(theta_nuevo - theta_anterior)
    orden          = len(historial) + 1

    # Guardar respuesta
    db_execute(conn,
        """INSERT INTO respuestas
           (sesion_id, item_id, orden, respuesta_dada, es_correcta,
            theta_post, sem_post, delta_theta)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
        (req.sesion_id, req.item_id, orden, req.respuesta_dada,
         es_correcta, theta_nuevo, sem_nuevo, delta_theta)
    )

    # Actualizar pasos sin cambio
    pasos_sin_cambio = sesion['pasos_sin_cambio']
    if delta_theta < DELTA_THETA_UMBRAL:
        pasos_sin_cambio += 1
    else:
        pasos_sin_cambio = 0

    # ── Criterio de parada ──────────────────────────────────────
    razon_parada = None
    if sem_nuevo < SEM_UMBRAL:
        razon_parada = 'precision'
    elif pasos_sin_cambio >= PASOS_ESTANCAMIENTO:
        razon_parada = 'estancamiento'

    nivel_actual = clasificar(theta_nuevo)

    # Registrar en panel investigador
    db_execute(conn,
        """INSERT INTO panel_investigador
           (sesion_id, usuario_id, paso, item_id, item_clave, item_b,
            es_correcta, theta, sem, ic_inf, ic_sup, nivel_momentaneo)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (req.sesion_id, sesion['usuario_id'], orden, req.item_id,
         item['clave'], item['b'], es_correcta, theta_nuevo, sem_nuevo,
         theta_nuevo - 1.96*sem_nuevo, theta_nuevo + 1.96*sem_nuevo,
         nivel_actual)
    )

    # Actualizar sesión
    if razon_parada:
        db_execute(conn,
            """UPDATE sesiones_examen SET
               estado='completado', theta_actual=%s, sem_actual=%s,
               pasos_sin_cambio=%s, n_items_respondidos=%s,
               nivel_resultado=%s, theta_final=%s, sem_final=%s,
               completado_at=NOW()
               WHERE id=%s""",
            (theta_nuevo, sem_nuevo, pasos_sin_cambio, orden,
             nivel_actual, theta_nuevo, sem_nuevo, req.sesion_id)
        )
        return {
            "examen_completado": True,
            "razon_parada": razon_parada,
            "nivel": nivel_actual,
            "theta_final": round(theta_nuevo, 3),
            "sem_final": round(sem_nuevo, 3),
            "n_items": orden,
            "es_correcta": bool(es_correcta)
        }

    db_execute(conn,
        """UPDATE sesiones_examen SET
           theta_actual=%s, sem_actual=%s,
           pasos_sin_cambio=%s, n_items_respondidos=%s
           WHERE id=%s""",
        (theta_nuevo, sem_nuevo, pasos_sin_cambio, orden, req.sesion_id)
    )

    return {
        "examen_completado": False,
        "es_correcta": bool(es_correcta),
        "theta_actual": round(theta_nuevo, 3),
        "sem_actual": round(sem_nuevo, 3),
        "nivel_momentaneo": nivel_actual,
        "paso": orden
    }

# --- Resultado final ---
@app.get("/examen/resultado/{usuario_id}")
def resultado(usuario_id: int, conn=Depends(get_db)):
    sesion = db_query(conn,
        "SELECT * FROM sesiones_examen WHERE usuario_id = %s",
        (usuario_id,), fetch='one'
    )
    if not sesion:
        raise HTTPException(404, "No se encontró sesión")

    return {
        "nivel": sesion['nivel_resultado'],
        "theta": sesion['theta_final'],
        "sem":   sesion['sem_final'],
        "ic_inf": round(sesion['theta_final'] - 1.96*sesion['sem_final'], 3) if sesion['theta_final'] else None,
        "ic_sup": round(sesion['theta_final'] + 1.96*sesion['sem_final'], 3) if sesion['theta_final'] else None,
        "n_items": sesion['n_items_respondidos'],
        "estado": sesion['estado']
    }

# ================================================================
# PANEL INVESTIGADOR (solo admins autenticados con JWT)
# ================================================================

# --- Lista de todas las sesiones ---
@app.get("/investigador/sesiones")
def panel_sesiones(admin=Depends(get_admin), conn=Depends(get_db)):
    sesiones = db_query(conn, "SELECT * FROM vista_sesiones ORDER BY updated_at DESC")
    return {"sesiones": sesiones}

# --- Trayectoria θ de un estudiante específico ---
@app.get("/investigador/trayectoria/{sesion_id}")
def trayectoria(sesion_id: int, admin=Depends(get_admin), conn=Depends(get_db)):
    eventos = db_query(conn,
        """SELECT paso, item_clave, item_b, es_correcta,
                  theta, sem, ic_inf, ic_sup, nivel_momentaneo, timestamp
           FROM panel_investigador
           WHERE sesion_id = %s ORDER BY paso""",
        (sesion_id,)
    )
    sesion = db_query(conn,
        "SELECT * FROM vista_sesiones WHERE sesion_id = %s",
        (sesion_id,), fetch='one'
    )
    return {"sesion": sesion, "trayectoria": eventos}