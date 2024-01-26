find .. -maxdepth 1 -type f | xargs tar cvf parent.tar.xz
docker build -t binex_project_compiler .
docker create --name binex_project_compiler binex_project_compiler
docker cp binex_project_compiler:/home/pwn/build/vuln .
docker rm -f binex_project_compiler
rm parent.tar.xz
