from flask import Flask, jsonify, request
from main import app, con
import re

from flask_bcrypt import generate_password_hash, check_password_hash


def validar_senha(senha):
    if len(senha) < 8:
        return jsonify({"error": "A senha deve conter pelo menos 8 caracteres"}), 400

    if not re.search(r"[!@#$%¨&*(),.?\":<>{}|]", senha):
        return jsonify({"error": "A senha deve conter pelo menos um símbolo especial"}), 400

    if not re.search(r"[A-Z]", senha):
        return jsonify({"error": "A senha deve conter pelo menos uma letra maiúscula"}), 400

    if len(re.findall(r"\d", senha)) < 2:
        return jsonify({"error": "A senha deve conter pelo menos dois números"}), 400

    return True

@app.route('/livros',methods=['GET'])
def livro():
    cursor = con.cursor()
    cursor.execute("SELECT id_livro, titulo, autor, ano_publicacao FROM livros")
    livros = cursor.fetchall()
    livros_dic = []
    for livro in livros:
        livros_dic.append({
            'id_livro': livro[0],
            'titulo': livro[1],
            'autor': livro[2],
            'ano_publicacao': livro[3]
        })

    return jsonify(mensagem='Lista de livros', livros=livros_dic)

@app.route('/livros', methods=['POST'])
def livros_post():
    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM LIVROS WHERE TITULO = ?" , (titulo,))

    if cursor.fetchone():
        return jsonify("Livro já cadastrado")

    cursor.execute("INSERT INTO LIVROS(TITULO, AUTOR, ANO_PUBLICACAO) VALUES (?,?,?)",
                   (titulo, autor, ano_publicacao))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro cadastrado com sucesso!",
        'livros': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })

@app.route('/livros/<int:id>', methods=['PUT'])
def livros_put(id):
    cursor = con.cursor()
    cursor.execute("select id_livro, titulo, autor, ano_publicacao from livros where id_livro = ?", (id,))
    livro_data = cursor.fetchone()

    if not livro_data:
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor.execute("UPDATE livros SET TITULO = ?, AUTOR = ?, ANO_Pu"
                   "BLICACAO = ? WHERE ID_LIVRO = ?",
                   (titulo, autor, ano_publicacao, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro atualizado com sucesso!",
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })

@app.route('/livros/<int:id>', methods=['DELETE'])
def deletar_livro(id):
    cursor = con.cursor()

    # Verificar se o livro existe
    cursor.execute("SELECT 1 FROM livros WHERE ID_LIVRO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    # Excluir o livro
    cursor.execute("DELETE FROM livros WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro excluído com sucesso!",
        'id_livro': id
    })







@app.route('/usuarios',methods=['GET'])
def usuarios():
    cursor = con.cursor()
    cursor.execute("SELECT id_usuario, nome, email, senha FROM usuarios")
    usuarios = cursor.fetchall()
    usuarios_dic = []
    for usuario in usuarios:
        usuarios_dic.append({
            'id_usuario': usuario[0],
            'nome': usuario[1],
            'email': usuario[2],
            'senha': usuario[3]
        })

    return jsonify(mensagem='Lista de usuarios', usuarios=usuarios_dic)

@app.route('/usuarios', methods=['POST'])
def usuarios_post():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM usuarios WHERE nome = ?" , (nome,))

    if cursor.fetchone():
        return jsonify("Usuario já cadastrado"), 400

    senha = generate_password_hash(senha).decode('utf-8')

    cursor.execute("INSERT INTO usuarios(nome, email, senha) VALUES (?,?,?)",
                   (nome, email, senha))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuario cadastrado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })


@app.route('/usuarios/<int:id>', methods=['PUT'])
def usuarios_put(id):
    cursor = con.cursor()
    cursor.execute("select id_usuario, nome, email, senha FROM usuarios where id_usuario = ?", (id,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({"error": "Usuario não encontrado"}), 404

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    cursor.execute("UPDATE usuarios SET nome = ?, email = ?, senha = ? WHERE ID_usuario = ?",
                   (nome, email, senha, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuario atualizado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })

@app.route('/usuarios/<int:id>', methods=['DELETE'])
def deletar_usuarios(id):
    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM usuarios WHERE ID_usuario = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuario não encontrado"}), 404
    cursor.execute("DELETE FROM usuarios WHERE ID_usuario = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuario excluído com sucesso!",
        'id_usuario': id
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({"error": "Todos os campos (email, senha) são obrigatórios."}), 400

    cursor = con.cursor()
    cursor.execute("SELECT SENHA FROM USUARIOS WHERE EMAIL = ?", (email,))
    usuario = cursor.fetchone()
    cursor.close()

    if not usuario:
        return jsonify({"error": "Usuario ou senha iválidos."}), 401

    senha_armazenada = usuario[0]

    if check_password_hash(senha_armazenada, senha):
        return jsonify({"message": "Login realizado com sucesso!"})

    return jsonify({"error": "Senha incorreta."})
