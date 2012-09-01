mod_blueprint
======

## INSTALL

    /path/to/apxs -c -Wall -I/path/to/apache/include/dir -I/path/to/include/dir -L/path/to/lib/dir -lz -lneo_cs -lneo_utl -lneo_cgi -lonig -i -a ./mod_blueprint.c


## CONF

    #
    # Blueprint
    #
    <IfModule blueprint_module>
    # default: cs
    # BlueprintTagName cs
        <Location "/">
            Order allow,deny
            Allow from all
            FilterDeclare BP CONTENT_SET
            FilterProvider BP Blueprint "%{CONTENT_TYPE} = 'text/plain'"
            FilterProvider BP Blueprint "%{CONTENT_TYPE} = 'text/html'"
            FilterProvider BP Blueprint "%{CONTENT_TYPE} = 'application/xhtml'"
            FilterProvider BP Blueprint "%{CONTENT_TYPE} = 'application/xhtml+xml'"
            FilterChain BP
        </Location>
    </IfModule>

