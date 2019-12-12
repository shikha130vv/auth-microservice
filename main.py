from project import create_app
from flask_migrate import Migrate

# Call the Application Factory function to construct a Flask application config
# using the standard configuration defined in /config/flask_dev.cfg
app, db = create_app('../config/flask_dev.cfg')
migrate = Migrate(app, db)