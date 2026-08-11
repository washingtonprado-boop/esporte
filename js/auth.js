/**
 * auth.js
 * -------------------------------------------------------------------------
 * Autenticação (Firebase Auth) + perfil/permissões (Firestore).
 *
 * Estrutura da coleção "usuarios" (doc.id === uid do Firebase Auth):
 *   {
 *     nome: string,
 *     email: string,
 *     tipo: "admin" | "responsavel",
 *     timeId: string | null,      // obrigatório quando tipo === "responsavel"
 *     status: "ativo" | "bloqueado",
 *     criadoEm: Timestamp
 *   }
 *
 * O cadastro de usuários é sempre feito/liberado pelo administrador
 * (ver admin.js) — não existe autocadastro público de usuário.
 * -------------------------------------------------------------------------
 */

import { auth, db } from "./firebase-config.js";
import {
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/10.13.0/firebase-auth.js";
import {
  doc,
  getDoc
} from "https://www.gstatic.com/firebasejs/10.13.0/firebase-firestore.js";

let currentUser = null;   // objeto do Firebase Auth
let currentProfile = null; // documento de usuarios/{uid}

/**
 * Faz login com e-mail e senha.
 * Lança erro com mensagem amigável em português em caso de falha.
 */
async function login(email, senha) {
  try {
    const cred = await signInWithEmailAndPassword(auth, email, senha);
    const profile = await carregarPerfil(cred.user.uid);

    if (!profile) {
      await signOut(auth);
      throw new Error("Usuário sem cadastro de perfil. Contate o administrador.");
    }
    if (profile.status === "bloqueado") {
      await signOut(auth);
      throw new Error("Este usuário está bloqueado. Contate o administrador.");
    }
    return profile;
  } catch (err) {
    throw new Error(traduzErroFirebase(err));
  }
}

async function logout() {
  await signOut(auth);
  currentUser = null;
  currentProfile = null;
  window.location.href = "login.html";
}

async function carregarPerfil(uid) {
  const snap = await getDoc(doc(db, "usuarios", uid));
  return snap.exists() ? { id: snap.id, ...snap.data() } : null;
}

function traduzErroFirebase(err) {
  const codigo = err.code || "";
  const mapa = {
    "auth/invalid-email": "E-mail inválido.",
    "auth/user-disabled": "Usuário desabilitado.",
    "auth/user-not-found": "E-mail ou senha incorretos.",
    "auth/wrong-password": "E-mail ou senha incorretos.",
    "auth/invalid-credential": "E-mail ou senha incorretos.",
    "auth/too-many-requests": "Muitas tentativas. Tente novamente mais tarde."
  };
  return mapa[codigo] || err.message || "Erro ao entrar. Tente novamente.";
}

/**
 * Protege uma página: exige autenticação e, opcionalmente, um tipo de
 * usuário específico. Redireciona para login.html quando não autorizado.
 *
 * Uso no topo de admin.html/js:
 *   const perfil = await requireAuth(["admin"]);
 *
 * Uso em equipe.html/js (admin OU responsável podem entrar):
 *   const perfil = await requireAuth(["admin", "responsavel"]);
 */
function requireAuth(tiposPermitidos = null) {
  return new Promise((resolve) => {
    onAuthStateChanged(auth, async (user) => {
      if (!user) {
        window.location.href = "login.html";
        return;
      }

      const profile = await carregarPerfil(user.uid);
      if (!profile || profile.status === "bloqueado") {
        await signOut(auth);
        window.location.href = "login.html";
        return;
      }

      if (tiposPermitidos && !tiposPermitidos.includes(profile.tipo)) {
        window.location.href = "acesso-negado.html";
        return;
      }

      currentUser = user;
      currentProfile = profile;
      resolve(profile);
    });
  });
}

function getPerfilAtual() {
  return currentProfile;
}

function isAdmin() {
  return currentProfile?.tipo === "admin";
}

function getTimeIdAtual() {
  return currentProfile?.tipo === "responsavel" ? currentProfile.timeId : null;
}

export {
  login,
  logout,
  requireAuth,
  getPerfilAtual,
  isAdmin,
  getTimeIdAtual
};
