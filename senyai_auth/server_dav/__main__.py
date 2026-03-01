import uvicorn
from . import SenyaiDAV

app = SenyaiDAV.create_app(debug=True)

uvicorn.run(app, host="127.0.0.1", port=5001)
