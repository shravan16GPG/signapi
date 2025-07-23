# Dockerfile
FROM node:18-alpine

WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy app code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Start the server
CMD ["npm", "start"]
