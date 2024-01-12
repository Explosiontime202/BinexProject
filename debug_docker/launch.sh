rm -f parent
find ..  -maxdepth 1 -type f | xargs tar cvf parent.tar.xz
docker container rm binex_project
docker image rm binex_project
docker build -t binex_project .
docker run -it -p 1337:1337 --cap-add=SYS_PTRACE --name binex_project binex_project
