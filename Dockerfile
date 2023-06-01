FROM node:18-alpine
WORKDIR /app
COPY ./.env ./
RUN apk add gcc musl-dev python3-dev libffi-dev 
RUN apk update && \
    apk add py-pip
RUN pip install azure-cli
COPY ./package.json ./
RUN npm install
COPY ./create.js ./
EXPOSE 3000
ENTRYPOINT [ "npm", "start" ]