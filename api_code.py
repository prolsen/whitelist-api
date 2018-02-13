from flask import Flask, request, jsonify

app = Flask(__name__)
app.config['HASH_FILE'] = '<PATH_TO_WHITELIST.txt>'

HASHES = None

# The app.route can be anything.
# Ex: http://192.168.1.3:1234/sysforensics/api/v0.1/hash/39<snip>26
@app.route('/sysforensics/api/v0.1/hash/<md5>', methods=['GET'])
def check_for_md5(md5):
    if request.method == 'GET':
        if md5 in HASHES:
                return jsonify(md5_hash=md5, in_set=True)
        return jsonify(md5_hash=md5,in_set=False)

if __name__ == '__main__':
	HASHES = set((h.strip() for h in open(app.config['HASH_FILE'], 'r')))
	# If you want this to be accessible to the outsite set it to 0.0.0.0
	# You can configure the port to anything.
	app.run(debug=True, host='192.168.1.3', port=1234)
