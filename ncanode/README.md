## Запуск

Build image: 
```
docker build -t malikzh/ncanode .
```
Run container: 
```
docker run -ti -p 14579:14579 malikzh/ncanode
```
## Документация

Документацию можно найти на http://ncanode.kz

### Примечание

Библиотеки kalkancrypt-0.6.jar и kalkancrypt_xmldsig-0.3.jar уже добавлены в директорию /lib.
