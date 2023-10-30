FROM python:3.8-slim-buster    

# Create app directory
WORKDIR /truenas_ldap_flask_tools
 
# Install app dependencies
COPY requirements.txt ./
 
RUN apt update
RUN apt install libsasl2-dev python-dev libldap2-dev libssl-dev -y

RUN pip install --upgrade pip 

RUN pip3 install -r requirements.txt
 
# Bundle app source
COPY . .

# RUN cd truenas_ldap_flask_tools/
EXPOSE 8443
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port","8443"]
