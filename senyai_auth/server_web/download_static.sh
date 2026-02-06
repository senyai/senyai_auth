echo "-----------------------------------------------------"
echo "-----------------------------------------------------"
echo "-----------------------------------------------------"
echo "NOTE: This script needs to be run from the dev folder"
echo "-----------------------------------------------------"
echo "-----------------------------------------------------"
echo "-----------------------------------------------------"

JS_DIR="static/js"
CSS_DIR="static/css"
FONTS_DIR="static/css/fonts"

# Create directories if they don't exist
mkdir -p "$JS_DIR"
mkdir -p "$CSS_DIR"
mkdir -p "$FONTS_DIR" # <-- Create fonts directory


echo "Starting download of dependencies..."

# Bootstrap JS Bundle (includes Popper.js)
if [ ! -f "$JS_DIR/bootstrap.bundle.min.js" ]; then
  echo "Downloading Bootstrap JS..."
  curl -L https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js -o "$JS_DIR/bootstrap.bundle.min.js"
else
  echo "Bootstrap JS already exists."
fi


# Bootstrap CSS
if [ ! -f "$CSS_DIR/bootstrap.min.css" ]; then
  echo "Downloading Bootstrap CSS..."
  # We will use a pre-compiled dark theme (Bootswatch "darkly")
  curl -L https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css -o "$CSS_DIR/bootstrap.min.css"
else
  echo "Bootstrap CSS already exists."
fi


# Download Bootstrap Icons CSS
if [ ! -f "$CSS_DIR/bootstrap-icons.min.css" ]; then
  echo "Downloading Bootstrap Icons CSS..."
  curl -L "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" -o "$CSS_DIR/bootstrap-icons.min.css"
else
  echo "Bootstrap Icons CSS already exists."
fi

# Download Bootstrap Icons Font File (WOFF2)
if [ ! -f "$FONTS_DIR/bootstrap-icons.woff2" ]; then
  echo "Downloading Bootstrap Icons WOFF2 Font..."
  curl -L "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff2" -o "$FONTS_DIR/bootstrap-icons.woff2"
else
  echo "Bootstrap Icons WOFF2 Font already exists."
fi

# Download Bootstrap Icons Font File (WOFF) - for broader compatibility
if [ ! -f "$FONTS_DIR/bootstrap-icons.woff" ]; then
  echo "Downloading Bootstrap Icons WOFF Font..."
  curl -L "https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff" -o "$FONTS_DIR/bootstrap-icons.woff"
else
  echo "Bootstrap Icons WOFF Font already exists."
fi

# Download htmx
if [ ! -f "$JS_DIR/htmx.min.js" ]; then
  echo "Downloading htmx..."
  curl -L "https://cdn.jsdelivr.net/npm/htmx.org@2.0.8/dist/htmx.min.js" -o "$JS_DIR/htmx.min.js"
else
  echo "htmx already exists."
fi


echo "----------------------------------------"
echo "Installation complete."
echo "----------------------------------------"