from security_framework.evaluators import misclassified_data
from security_framework.initializer import Initializer
from security_framework.gkg import GKG
from sklearn.ensemble import RandomForestClassifier
from preprocessing.processing import get_train_data, get_test_data

if __name__ == '__main__':
    x, y = get_train_data("caida")
    tx, ty = get_test_data("global")

    gkg = GKG()

    # Entity A Initialization
    Entity_A = Initializer()
    Entity_A.set_init_parameters(gkg.setup(256, 256, Entity_A.OTCP), gkg.KPP)

    # Entity B Initialization
    Entity_B = Initializer()
    Entity_B.set_init_parameters(gkg.setup(256, 256, Entity_B.OTCP), gkg.KPP)

    # Mutual Entities Authentication
    # Entity A generates a hash using Entity B's public key and transmits it to Entity B. Public keys KPP are
    # retrievable from the registry but since this is done in a single file, entity objects will be used.
    h_A = Entity_A.gen_auth_hash(Entity_B.KPP)
    is_A_authenticated = Entity_B.auth_entity(Entity_A.KPP, h_A)
    print("Entity A is authenticated by Entity B: ", is_A_authenticated)

    # Entity B repeats the same for Entity A
    h_B = Entity_B.gen_auth_hash(Entity_A.KPP)
    is_B_authenticated = Entity_A.auth_entity(Entity_B.KPP, h_B)
    print("Entity B is authenticated by Entity A: ", is_B_authenticated)

    print("Commencing a session...")
    Entity_A_KP = Entity_A.gen_session_keys(Entity_B.KPP)
    Entity_B_KP = Entity_B.gen_session_keys(Entity_A.KPP)

    # Assuming model belongs to Entity A and he wants to sent 5 of it's misclassified flows to Entity B for help.
    model = RandomForestClassifier(n_estimators=100).fit(x, y)
    mis = misclassified_data(model, tx, ty, 70)
    first_five = mis[:5].values

    # Entity A encrypts the message and generate a MAC
    cipher = Entity_A.encrypt(first_five, Entity_A.gen_session_symmetric_key(Entity_B_KP))
    Entity_A_MAC = Entity_A.gen_mac(Entity_B_KP, cipher)

    # Entity B verifies the message and decrypts it.
    print("Cipher is authenticated: ", Entity_B.verify_mac(cipher, Entity_A_KP, Entity_A_MAC))
    message = Entity_B.decrypt(cipher, Entity_B.gen_session_symmetric_key(Entity_A_KP), dim=19)

    print("Decrypted message same as sent message: ", (first_five == message).all())
    # print("The current state of the entity is: ", check_state(cumulative_trust, peak_trust=10))
