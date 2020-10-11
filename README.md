# File Uploader
It's a Node.js App where you can SignIn/Login, upload the files and also read/update/download it. Database: PostgreSQL 
# How to use it ?
 - Create a file `.env` at the root of the project
 - Create a folder `uploads` also at the root of the project
 - Add your PostgreSQL credentials to the .env file

 ```
.env file

DB_USER=
DB_PASSWORD=
DB_HOST=
DB_PORT=
DB_DATABASE=

SESSION_SECRET=
```
- Сreate two tables in the database (the description of which is in the ```tables.sql``` file)
- In order to run this project open terminal and run the command ```npm run dev```
---

### That's all :D

Copyright (c) 2020 LakerShot

