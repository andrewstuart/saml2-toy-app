FROM golang
MAINTAINER Andrew Stuart <andrew.stuart2@gmail.com>
ENTRYPOINT /saml2-toy-app
EXPOSE 8080

ADD saml2-toy-app /
