# Removes system profiles and bashrc

mkdir /opt/quarentine

mv /etc/prof{i,y}le* /opt/quarentine

for file in '.profile' '.bashrc' '.bash_login' '.zshrc'; do
    find /home /root -name "$file" -exec rm {};;
done