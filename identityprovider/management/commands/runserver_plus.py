from optparse import make_option

import django

from django.core.handlers.wsgi import WSGIHandler
from django.core.management.base import BaseCommand, CommandError
from django.core.servers.basehttp import AdminMediaHandler


def null_technical_500_response(request, exc_type, exc_value, tb):
    raise exc_type, exc_value, tb


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option(
            '--noreload', action='store_false', dest='use_reloader',
            default=True, help='Tells Django to NOT use the auto-reloader.',
        ),
        make_option(
            '--adminmedia', dest='admin_media_path', default='',
            help='Specifies the directory from which to serve admin media.',
        ),
    )
    help = "Starts a lightweight Web server for development."
    args = '[optional port number, or ipaddr:port]'

    # Validation is called explicitly each time the server is reloaded.
    requires_model_validation = False

    def handle(self, addrport='', *args, **options):
        try:
            from werkzeug import run_simple, DebuggedApplication
            from werkzeug.serving import WSGIRequestHandler
        except ImportError, e:
            raise e
        except:
            msg = ("Werkzeug is required to use runserver_plus.  "
                   "Please visit http://werkzeug.pocoo.org/download")
            raise CommandError(msg)

        class DebugWSGIRequestHandler(WSGIRequestHandler):

            def make_environ(self):
                # Add the 'wsgi.handleErrors' key to the wsgi environment
                # so that lazr.restful doesn't do its own error handling.
                environ = super(DebugWSGIRequestHandler, self).make_environ()
                environ['wsgi.handleErrors'] = False
                return environ

        # usurp django's handler
        from django.views import debug
        debug.technical_500_response = null_technical_500_response

        if args:
            raise CommandError('Usage is runserver %s' % self.args)
        if not addrport:
            addr = ''
            port = '8000'
        else:
            try:
                addr, port = addrport.split(':')
            except ValueError:
                addr, port = '', addrport
        if not addr:
            addr = '127.0.0.1'

        if not port.isdigit():
            raise CommandError("%r is not a valid port number." % port)

        use_reloader = options.get('use_reloader', True)
        admin_media_path = options.get('admin_media_path', '')

        def inner_run():
            from django.conf import settings
            print "Validating models..."
            self.validate(display_num_errors=True)
            print "\nDjango version %s, using settings %r" % (
                django.get_version(), settings.SETTINGS_MODULE)
            print "Development server is running at http://%s:%s/" % (
                addr, port)
            print "Using the Werkzeug debugger (http://werkzeug.pocoo.org/)"
            print "Quit the server with CONTROL-C."
            path = admin_media_path or (django.__path__[0] +
                                        '/contrib/admin/media')
            handler = AdminMediaHandler(WSGIHandler(), path)
            run_simple(addr, int(port), DebuggedApplication(handler, True),
                       use_reloader=use_reloader, use_debugger=True,
                       threaded=True, request_handler=DebugWSGIRequestHandler)
        inner_run()
