from faker import Faker
from email.parser import Parser
from functools import lru_cache
from urllib.parse import parse_qs, urlparse
from random import randint
import json
import sys
import socket


MAX_LINE = 64*1024
MAX_HEADERS = 100
PREGEN_CHARACTERS = 100

class HTTPError(Exception):
  def __init__(self, status, reason, body=None):
    super()
    self.status = status
    self.reason = reason
    self.body = body

class Response:
  def __init__(self, status, reason, headers=None, body=None):
    self.status = status
    self.reason = reason
    self.headers = headers
    self.body = body

class Request:
  def __init__(self, method, target, version, headers, rfile):
    self.method = method
    self.target = target
    self.version = version
    self.rfile = rfile
    self.headers = headers
class Pregen:
  def generate_characters(amount):
    users = {}
    for person in range(amount):
      generator = Faker()
      name = generator.name()
      address = generator.address()
      age = randint(0,100)
      if (randint(0,1) == 0):
        premium_user = False
      else:
        premium_user = True
      users[person] = { 'id': person,
                        'name': name,
                        'address' : address,
                        'age': age,
                        'premium_user' : premium_user
                      }
    
    return users
    
@property
def path(self):
  return self.url.path

@property
@lru_cache(maxsize=None)
def query(self):
  return parse_qs(self.url.query)

@property
@lru_cache(maxsize=None)
def url(self):
  return urlparse(self.target)  


class MyHTTPServer:
  def __init__(self, host, port, server_name):
    self._host = host
    self._port = port
    self._server_name = server_name
    #self._users = Pregen.generate_characters(PREGEN_CHARACTERS)
    self._users = {}



  def serve_forever(self):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=0) as serv_sock:
      serv_sock.bind((self._host, self._port))
      serv_sock.listen()
      while True:
        conn, _ = serv_sock.accept()
        print('Client accepted!')
        try:
          self.serve_client(conn)
        except Exception as e:
          print('Client serving failed', e)

  def serve_client(self, conn):
    try:
      req = self.parse_request(conn)
      resp = self.handle_request(req)
      self.send_response(conn, resp)
    except ConnectionResetError:
      conn = None
    except Exception as e:
      self.send_error(conn, e)

    if conn:
      conn.close()

  def parse_request(self, conn):
    rfile = conn.makefile('rb')
    method, target, ver = self.parse_request_line(rfile)
    headers = self.parse_headers(rfile)
    host = headers.get("Host")
    if not host:
      raise Exception("Bad request")
    #if host not in (self._server_name, f'{self._server_name}:{self._port}'):       Нужна ли эта проверка?
    #  raise Exception("Not found")
    return Request(method, target, ver, headers, rfile)
  
  def parse_headers(self, rfile):
    headers = []
    while True:
      line = rfile.readline(MAX_LINE + 1)
      if len(line) > MAX_LINE:
        raise Exception('Header line is too long')

      if line in (b'\r\n', b'\n', b''):
        break

      headers.append(line)
      if len(headers) > MAX_HEADERS:
        raise Exception('Too many headers')
      
    sheaders = b''.join(headers).decode('iso-8859-1')
    return Parser().parsestr(sheaders)
  
  def parse_request_line(self, rfile):
    raw = rfile.readline(MAX_LINE + 1)
    if (len(raw) > MAX_LINE):
      raise Exception('Request line is too long')
    
    req_line = str(raw, 'iso-8859-1')
    req_line = req_line.rstrip('\r\n')
    words = req_line.split()            # разделяем по пробелу
    if len(words) != 3:                 # и ожидаем ровно 3 части
      raise Exception('Malformed request line')

    method, target, ver = words
    if ver != 'HTTP/1.1':
      raise Exception('Unexpected HTTP version')

    return [method, target, ver]
  
  def handle_request(self, req):
    if req.path == '/users' and req.method == 'POST':
      return self.handle_post_users(req)
    
    if req.path == '/users' and req.method == 'GET':
      return self.handle_get_users(req)

    if req.path.startswith('/users/'):
      user_id = req.path[len('/users/'):]
      if user_id.isdigit():
        return self.handle_get_user(req, user_id)

    raise HTTPError(404, 'Not found')
  
  def handle_post_users(self, req):
    print('aboba')
    user_id = len(self._users) + 1
    self._users[user_id] = {'id': user_id,
                            'name': req.query['name'][0],
                            'address' : req.query['address'][0],
                            'age': req.query['age'][0],
                            'premium_user' : req.query['premium_user'][0]
                            }
    return Response(204, 'Created')
  
  def handle_get_users(self, req):
    accept = req.headers.get('Accept')
    if 'application/json' in accept:
      content_type = 'application/json; charset=utf-8'
      body = json.dumps(self._users)
    else:
      return Response(406, 'Not Acceptable')
    
    body = body.encode('utf-8')
    headers = [('Content-Type', content_type),
               ('Content-Length', len(body))]
    return Response(200, 'OK', headers, body)
  
  def send_response(self, conn, resp):
    wfile = conn.makefile('wb')
    status_line = f'HTTP/1.1 {resp.status} {resp.reason}\r\n'
    wfile.write(status_line.encode('iso-8859-1'))

    if resp.headers:
      for (key, value) in resp.headers:
        header_line = f'{key}: {value}\r\n'
        wfile.write(header_line.encode('iso-8859-1'))

    wfile.write(b'\r\n')

    if resp.body:
      wfile.write(resp.body)

    wfile.flush()
    wfile.close()

  def send_error(self, conn, err):
    try:
      status = err.status
      reason = err.reason
      body = (err.body or err.reason).encode('utf-8')
    except:
      status = 500
      reason = b'Internal Server Error'
      body = b'Internal Server Error'
    resp = Response(status, reason,
                   [('Content-Length', len(body))],
                   body)
    self.send_response(conn, resp)

if __name__ == '__main__':
  host = '127.0.0.1'
  port = 65432
  name = 'localhost:65432'

  serv = MyHTTPServer(host, port, name)
  try:
    serv.serve_forever()
  except KeyboardInterrupt:
    pass