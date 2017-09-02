from flask import render_template, request, jsonify
from . import main


# 向Web服务客户端发送JSON格式响应  内容协商
@main.app_errorhandler(403)
def forbidden(e):
    if request.accept_mimetypes_json and \
            not request.accept_mimetypes.accept_html:
        reponse = jsonify({'error': 'forbidden'})
        reponse.status_code = 403
        return reponse
    return render_template('403.html'), 403


@main.app_errorhandler(404)
def page_not_found(e):
    if request.accept_mimetypes_json and \
            not request.accept_mimetypes.accept_html:
        reponse = jsonify({'error': 'not found'})
        reponse.status_code = 404
        return reponse
    return render_template('404.html'), 404


@main.app_errorhandler(500)
def internal_server_error(e):
    if request.accept_mimetypes_json and \
            not request.accept_mimetypes.accept_html:
        reponse = jsonify({'error': 'internal server error'})
        reponse.status_code = 500
        return reponse
    return render_template('500.html'), 500
