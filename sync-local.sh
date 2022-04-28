printf "syzkaller modifications... "
pushd "$SERENITY_SOURCE_DIR/Build/$SERENITY_ARCH/"

# add key /root/.ssh/authorized_keys
if [ -z "$PUBKEY" ]; then
    echo "Please set the PUBKEY env var to your ssh pubkey"
    exit 1
fi
mkdir -p mnt/root/.ssh
chmod 700 mnt/root/.ssh/
echo "$PUBKEY" > mnt/root/.ssh/authorized_keys
chmod 600 mnt/root/.ssh/authorized_keys
chown -R 0:0 mnt/root/

# the scp binary from the openssh port ends up here. scp invokes
# another scp on the receiving end, expecting it to be in the path
echo "export PATH=/usr/local/bin/:$PATH" > mnt/root/.shellrc

# enable openssh server
cat <<EOF >> mnt/etc/SystemServer.ini

[SSHServer]
Executable=/usr/local/sbin/sshd
Arguments=-D
KeepAlive=1
SystemModes=text,graphical
EOF

popd
echo "done"