from aiohttp import web

from plone.oauth import  main

app = main('./config.json')
web.run_app(app)