set -e

mkdir public
mkdir private

# private folder
cp exploit/exploit.py private
cp activation_key.txt private
cp release_docker/README.md private
cp release_docker/Dockerfile private

# compile vuln
cd compile_docker
./compile.sh
cd ..

# public folder
cp compile_docker/vuln public
cp vuln.c public
cp release_docker/Dockerfile public

echo "Pinguine toll Pinguine toll Pinguine super" >public/activation_key.txt

# packing
tar -zcvf submission_team203.tar.gz public private

# cleanup
rm compile_docker/vuln
rm -r private
rm -r public
