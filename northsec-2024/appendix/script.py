from flag import FLAG

import requests

from flask import Flask, request
from markupsafe import escape
from urllib.parse import urlsplit, urlunsplit
from textwrap import dedent

app = Flask(__name__)

# Prognostic: 
#   There is an issue with the delivery of the beneficial bacterias.
#   It seems to be related to this part of the appendix
def malfunction(destination):
    if(not destination):
        return ''

    (scheme, host, path, query, fragment) = urlsplit(destination)
    return urlunsplit(('', '', path, query, fragment))

@app.route('/', methods=["GET"])
def index():
    destination = ''
    message = dedent(
        """
            <hr>
            <pre>
            Tell me where to send the beneficial bacterias.
            I'm having issues these days, here's the <a href="/?pronostic">pronostic.</a>
            </pre>
        """
    )
    if('pronostic' in request.args):
        with open(__file__, 'r') as f:
            content = f.read()
        message = dedent(f"<hr><pre>{escape(content)}</pre>")
    else:
        destination = malfunction(request.args.get('destination', ''))
        if(destination):
            try:
                requests.get(destination)
            except requests.exceptions.ConnectionError as connectionError:
                message = dedent(
                    f"""
                        <hr>
                        <pre>
                        Failed to deliver beneficial bacterias: {escape(destination)}
                        Message: {escape(connectionError)}
                        </pre>
                    """
                )
            except ValueError as valueError:
                message = dedent(
                    f"""
                        <hr>
                        <pre>
                        Invalid destination: {escape(destination)}
                        Message: {escape(valueError)}
                        </pre>
                    """
                )
            else:
                requests.get(f"{destination}?flag={FLAG}")
                message = dedent(
                    """
                        <hr>
                        <pre>
                        Beneficial bacterias successfully delivered.
                        </pre>
                    """
                )
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Appendix</title>
    <style>
        * {{
            background-color: #ab4f69;
            color: #c9c097;
        }}

        input, pre {{
            background-color: #ab9a4f;
            border: 5px inset;
            border-radius: 12px;
            padding: 8px;
            margin: 5px;
            color: #451626;
        }}
    </style>
</head>
<body>
    <h1>Welcome to the appendix</h1>
    <form action="/" method="get">
        <label for="destination">Destination: </label>
        <input type="text" name="destination" value="{escape(destination)}">
        <input type="submit">
    </form>
    {message}
</body>
</html>"""
