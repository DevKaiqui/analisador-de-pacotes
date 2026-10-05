package br.com.analisador;

import br.com.analisador.detector.Mascara;

/** Oculta parte de IPs e MACs para não expor dados da rede na saída. */
public final class SensitiveDataMasker {

    public String maskIp(String ip, boolean mostrarSensivel) {
        if (ip == null || mostrarSensivel) return ip;
        if (ip.contains(":")) {
            String[] partes = ip.split(":");
            return partes.length > 2 ? partes[0] + ":" + partes[1] + ":****" : ip;
        }
        String[] octetos = ip.split("\\.");
        if (octetos.length != 4) return ip;
        return octetos[0] + "." + octetos[1] + ".x.x";
    }

    public String maskMac(String mac, boolean mostrarSensivel) {
        if (mac == null || mostrarSensivel) return mac;
        String[] partes = mac.split("[:-]");
        if (partes.length != 6) return mac;
        return partes[0] + ":" + partes[1] + ":" + partes[2] + ":**:**:**";
    }

    public Mascara comoMascara(boolean mostrarSensivel) {
        return new Mascara(ip -> maskIp(ip, mostrarSensivel), mac -> maskMac(mac, mostrarSensivel));
    }
}
