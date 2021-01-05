from bls.scheme import *


print("****************SETUP**************")

#m = [3, 4, 6, 1, 8, 3] # messages
m = ["MyVerySecretCode"]

print("Test scenario: threshold signature based on Bilinear Pairing on EC.")

t, n = 3, 4 # number of authorities
print("Authorities: ", n, ". Threshold required: ", t)


params = setup()
print("Generating the groups G1, G2 and GT and defining the pair function (G1,G2) -> GT")

input()
print("***************KEYS GENERATION****************")

(sk, vk) = ttp_keygen(params, t, n)
print("Generating a keypair for Alice, Bob and Eve")
print("Alice's secret key: ", sk[0])
print("Alcie's verification key: ", vk[0].export().hex())
print("Bob's secret key: ", sk[1])
print("Bob's verification key: ", vk[1].export().hex())
print("Eve's secret key: ", sk[2])
print("Eve's verification key: ", vk[2].export().hex())
print("Foo's secret key: ", sk[3])
print("Foo's verification key: ", vk[3].export().hex())

input()
print("*************AGGREGATED VERIFICATION KEY*************")

aggr_vk = aggregate_vk(params, vk)
print("Generating aggregated verification key: ", aggr_vk.export().hex())

input()
print("**************ALICE, BOB AND EVE SIGN*********************")

sig0 = sign(params, sk[0], m)
print("Creating Alice signature: ", sig0.export().hex())
sig1 = sign(params, sk[1], m)
print("Creating Bob signature: ", sig1.export().hex())
sig2 = sign(params, sk[2], m)
print("Creating Eve signature: ", sig2.export().hex())

sigma = aggregate_sigma(params, [sig0, sig1, sig2, None])
print("Alice, Bob and Eve's aggregated signature is: ", sigma.export().hex())

input()
print("**************VERIFICATION*********************")


print("The signature given is: ", verify(params, aggr_vk, sigma, m))

input()
print("**************ONLY BOB AND FOO SIGNS*********************")

sig1 = sign(params, sk[1], m)
print("Creating Bob signature: ", sig1.export().hex())
sig3 = sign(params, sk[3], m)
print("Creating Foo signature: ", sig3.export().hex())

sigma = aggregate_sigma(params, [None, sig1, None, sig3])
print("Bob and Foo's aggregated signature is: ", sigma.export().hex())

input()
print("**************WRONG VERIFICATION*********************")


print("The signature given is: ", verify(params, aggr_vk, sigma, m))
