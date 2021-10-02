from flask import abort
import jwt
from datetime import datetime
import redis
import json
import hashlib
from flask import request
from flask_restful import Resource,Api
from flask import Flask
from flask import Flask
from flask_cors import CORS

jwtSecret='TZxGjmunpRY *{ qR)Y{f{^&PKzEU8M1eQZPtUF`+a%Y;Qh?h7p(kc-XZHKbJdU,'

def firmaHash(contenido, usuarioId):
    toHash=str(usuarioId)+"-"+str(contenido)
    hash_object= hashlib.sha256(toHash.encode())
    return hash_object.hexdigest()

def searchByField(collection, searchForCollection, field1, valueToSearch1,field2=None, valueToSearch2=None):
    output=[]
    for value in collection:
        item=json.loads(collection[value])
        if item[field1]==valueToSearch1:
            if field2 is None:
                if searchForCollection==True:
                    output.append(item)
                else:
                    return item
            else:
                if item[field2]==valueToSearch2:
                    if searchForCollection==True:
                        output.append(item)
                    else:
                        return item
            
    if searchForCollection==True:
        return output
    else:
        return None

def generateToken(user):
    return jwt.encode(user, jwtSecret, algorithm="HS256")

def jwtAuthorize(token):
    try:
        return jwt.decode(token, jwtSecret, algorithms=["HS256"])
    except:
        return None


def createLogEntry(evento):
    now=datetime.now()
    newLogEntry={"date" : now.strftime("%m/%d/%Y, %H:%M:%S.%f") , "event" : evento }
    redisInstance.lpush("tbl_log",json.dumps(newLogEntry))


def toString(bArray):    
    try:
        return bArray.decode("utf-8")
    except ValueError:
        return "error"


redisInstance = redis.Redis(
    host='ec2-50-19-196-205.compute-1.amazonaws.com', 
    port=17830,
    password="p8246bd54e4335f5d4001090409c247e242ebbc0d28a3a9a8f92400e7b9e1d178",
    ssl=True,
    ssl_cert_reqs=None,
    charset="utf-8",
    decode_responses=True
    )

#Obtener todos los usuarios de la base de datos
#esto devuelve un 

#tabla de usuarios
tbl_usuarios=redisInstance.hgetall("tbl_usuario")
#tabla de acciones vs tipo de usuario para autenticacion
tbl_tipo_accion = redisInstance.hgetall("tbl_tipo_accion")
#tabla cobros pendientes
tbl_cobros_pendientes = redisInstance.hgetall("tbl_cobros_pendientes")

#tabla historias clinicas
tbl_historia_clinica = redisInstance.hgetall("tbl_historia_clinica")


# Obtener un token desde una peticion a un metodo FLASK
app = Flask(__name__)
app_context = app.app_context()
app_context.push()

api = Api(app)
CORS(app)


@app.route('/gestorSeguridad/authenticateUser', methods=['GET', 'POST'])
def authenticateUser():
    evento="authenticateUser for " + toString(request.data)
    try:
        content = request.json
        user=searchByField(tbl_usuarios,False,"username",content['username'],"password",content['password'])    
        if (user==None):
            evento= evento + " fallido"
            createLogEntry(evento)
            abort(404)
        else:            
            token=generateToken(user)
            evento= evento + " exitoso con token " + token
            createLogEntry(evento)
            return {"token" : token}            
    except:
        evento=evento+ " fallido"
        createLogEntry(evento)
        abort(404)


@app.route('/gestorSeguridad/authorizeToken', methods=['GET', 'POST'])
def authorizeToken():
    evento="authorizeToken for " + toString(request.data)
    try:
        content = request.json
        user= jwtAuthorize(content["token"])
        if (user==None):
            evento=evento+" fallido"
            createLogEntry(evento)
            abort(404)
        else:            
            evento=evento+" exitoso para usuario "+ str(user["id"])
            createLogEntry(evento)
            return user           
    except:
        evento=evento+" fallido"
        createLogEntry(evento)
        abort(404)

@app.route('/gestorSeguridad/authorizeAction', methods=['GET', 'POST'])
def authorizeAction():
    evento="authorizeAction for " + toString(request.data)
    try:
        content = request.json
        user=searchByField(tbl_usuarios,False,"id",content["usuarioId"])
        if (user==None):
            evento=evento+ " fallido"
            createLogEntry(evento)
            abort(404)
        else:                  
            isAutorized=searchByField(tbl_tipo_accion,False,"tipoId", user["tipoId"] , "accionId" , content["accionId"])                              
            if isAutorized==None:
                evento=evento+ " fallido"
                createLogEntry(evento)
                abort(404)
            else:                
                evento=evento+ " exitoso"
                createLogEntry(evento)
                return {"autorization" : True }
    except:
        evento=evento+" fallido"
        createLogEntry(evento)
        abort(404)


@app.route('/gestorSeguridad/hashContent', methods=['GET', 'POST'])
def hashContent():
    evento="hashContent for " + toString(request.data)
    try:
        content = request.json
        user=searchByField(tbl_usuarios,False,"id",content["usuarioId"])
        if (user==None):
            evento=evento+" fallido"
            createLogEntry(evento)
            abort(404)
        else:      
            evento=evento+" exitoso"
            createLogEntry(evento)
            return {"hash": firmaHash(content["contenido"],user["id"]) }            
    except:
        evento=evento+" fallido"
        createLogEntry(evento)
        abort(404)


if __name__ == '__main__':
    app.run(debug=True)