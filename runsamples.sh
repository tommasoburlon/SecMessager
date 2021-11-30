
cd ./samples/users
for FILE in *;
do
  cd $FILE;
  gnome-terminal -- ./client;
  cd ..;
done

cd ./../server;

gnome-terminal --  ./server;

cd ../..
