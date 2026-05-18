FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --only=production
COPY src/ ./src/
# Non-root user
USER node
EXPOSE 3000
CMD ["node", "src/app.js"]