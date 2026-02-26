import uvicorn
from . import app

uvicorn.run(app, host="127.0.0.1", port=5001)
