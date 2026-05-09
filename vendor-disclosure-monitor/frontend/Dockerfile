FROM node:20-alpine

WORKDIR /app

COPY frontend/package*.json /app/
RUN npm install

COPY frontend /app

EXPOSE 3000

CMD ["npm", "run", "dev", "--", "-H", "0.0.0.0", "-p", "3000"]
