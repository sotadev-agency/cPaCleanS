const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, PageNumber, PageBreak, LevelFormat, ExternalHyperlink
} = require("docx");

const border = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
const borders = { top: border, bottom: border, left: border, right: border };
const cellMargins = { top: 60, bottom: 60, left: 100, right: 100 };

const BLUE = "1B4F72";
const LIGHT_BLUE = "D6EAF8";
const DARK = "2C3E50";
const RED = "E74C3C";
const GREEN = "27AE60";
const ORANGE = "E67E22";

function heading(text, level) {
  return new Paragraph({ heading: level, spacing: { before: level === HeadingLevel.HEADING_1 ? 360 : 240, after: 120 }, children: [new TextRun({ text, bold: true })] });
}

function para(text, opts = {}) {
  return new Paragraph({ spacing: { after: 120 }, ...opts, children: [new TextRun({ text, size: 22, font: "Arial", ...opts.run })] });
}

function boldPara(label, text) {
  return new Paragraph({ spacing: { after: 100 }, children: [
    new TextRun({ text: label, bold: true, size: 22, font: "Arial" }),
    new TextRun({ text, size: 22, font: "Arial" }),
  ]});
}

function bullet(text, ref) {
  return new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text, size: 22, font: "Arial" })] });
}

function numberedItem(text, ref) {
  return new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 60 }, children: [new TextRun({ text, size: 22, font: "Arial" })] });
}

function headerCell(text, width) {
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA },
    shading: { fill: BLUE, type: ShadingType.CLEAR },
    margins: cellMargins,
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: "FFFFFF", size: 20, font: "Arial" })] })]
  });
}

function cell(text, width, opts = {}) {
  return new TableCell({
    borders, width: { size: width, type: WidthType.DXA },
    shading: opts.fill ? { fill: opts.fill, type: ShadingType.CLEAR } : undefined,
    margins: cellMargins,
    children: [new Paragraph({ children: [new TextRun({ text, size: 20, font: "Arial", bold: opts.bold, color: opts.color })] })]
  });
}

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 36, bold: true, font: "Arial", color: BLUE },
        paragraph: { spacing: { before: 360, after: 200 }, outlineLevel: 0 } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 28, bold: true, font: "Arial", color: DARK },
        paragraph: { spacing: { before: 280, after: 140 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 24, bold: true, font: "Arial", color: DARK },
        paragraph: { spacing: { before: 200, after: 100 }, outlineLevel: 2 } },
    ]
  },
  numbering: {
    config: [
      { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "nums2", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "nums3", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
      { reference: "nums4", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    ]
  },
  sections: [
    // ── PORTADA ──
    {
      properties: {
        page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }
      },
      children: [
        new Paragraph({ spacing: { before: 3000 } }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 }, children: [
          new TextRun({ text: "cPacleanS", size: 72, bold: true, font: "Arial", color: BLUE }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [
          new TextRun({ text: "v2.0.0", size: 36, font: "Arial", color: DARK }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 }, children: [
          new TextRun({ text: "Manual de Usuario", size: 32, font: "Arial", color: "7F8C8D" }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 100 }, children: [
          new TextRun({ text: "Limpiador profesional de malware para backups cPanel", size: 24, font: "Arial", color: "7F8C8D" }),
        ]}),
        new Paragraph({ spacing: { before: 2000 } }),
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [
          new TextRun({ text: "SotaDev Agency", size: 22, font: "Arial", color: DARK }),
        ]}),
        new Paragraph({ alignment: AlignmentType.CENTER, children: [
          new TextRun({ text: "Junio 2026", size: 20, font: "Arial", color: "95A5A6" }),
        ]}),
      ]
    },
    // ── CONTENIDO ──
    {
      properties: {
        page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } }
      },
      headers: {
        default: new Header({ children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 4 } },
          children: [
            new TextRun({ text: "cPacleanS v2.0.0 — Manual de Usuario", size: 16, font: "Arial", color: "95A5A6" }),
          ]
        })] })
      },
      footers: {
        default: new Footer({ children: [new Paragraph({
          alignment: AlignmentType.CENTER,
          children: [
            new TextRun({ text: "Pagina ", size: 16, font: "Arial", color: "95A5A6" }),
            new TextRun({ children: [PageNumber.CURRENT], size: 16, font: "Arial", color: "95A5A6" }),
          ]
        })] })
      },
      children: [
        // === QUE ES ===
        heading("1. Que es cPacleanS", HeadingLevel.HEADING_1),
        para("Herramienta de escritorio para Windows que escanea y limpia malware en copias de seguridad generadas desde cPanel. Soporta WordPress, Moodle, Joomla, Laravel y codigo PHP/HTML/JS/CSS propio."),
        para("Utiliza todos los procesadores del equipo para maximizar la velocidad de escaneo y genera reportes profesionales en HTML y PDF."),

        // === INSTALACION ===
        heading("2. Instalacion", HeadingLevel.HEADING_1),
        numberedItem("Ejecutar cPacleanS_Setup_v2.0.0.exe", "numbers"),
        numberedItem("Seguir el asistente de instalacion", "numbers"),
        numberedItem("Abrir desde el acceso directo en el escritorio o menu inicio", "numbers"),
        para(""),
        boldPara("Requisito: ", "Windows 10/11 de 64 bits"),

        // === USO RAPIDO ===
        heading("3. Uso rapido (3 pasos)", HeadingLevel.HEADING_1),

        heading("Paso 1: Seleccionar backup", HeadingLevel.HEADING_2),
        bullet("Hacer click en Explorar y seleccionar el archivo .tar.gz descargado de cPanel", "bullets"),
        bullet("Formatos soportados: .tar.gz, .tgz, .zip, .gz, .tar", "bullets"),

        heading("Paso 2: Elegir modo de operacion", HeadingLevel.HEADING_2),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [2200, 3580, 3580],
          rows: [
            new TableRow({ children: [headerCell("Modo", 2200), headerCell("Que hace", 3580), headerCell("Cuando usarlo", 3580)] }),
            new TableRow({ children: [cell("Solo Escaneo", 2200, {bold:true}), cell("Genera reporte sin tocar archivos", 3580), cell("Diagnostico inicial, auditorias", 3580)] }),
            new TableRow({ children: [cell("Normal", 2200, {bold:true, color:GREEN}), cell("Solo malware confirmado a cuarentena", 3580, {fill:LIGHT_BLUE}), cell("Uso recomendado, seguro", 3580, {fill:LIGHT_BLUE})] }),
            new TableRow({ children: [cell("Intermedio", 2200, {bold:true, color:ORANGE}), cell("Confirmados + alta severidad a cuarentena", 3580), cell("Cuentas con mucha infeccion", 3580)] }),
            new TableRow({ children: [cell("Estricto", 2200, {bold:true, color:RED}), cell("TODO lo sospechoso eliminado", 3580), cell("Ultima opcion, mas agresivo", 3580)] }),
          ]
        }),

        heading("Paso 3: Click en INICIAR", HeadingLevel.HEADING_2),
        para("La aplicacion ejecuta automaticamente:"),
        numberedItem("Extraccion del backup", "nums2"),
        numberedItem("Escaneo multiprocessing (usa todos los CPUs)", "nums2"),
        numberedItem("Consulta VirusTotal (si hay API key configurada)", "nums2"),
        numberedItem("Restauracion de CMS desde repositorios oficiales", "nums2"),
        numberedItem("Limpieza segun el modo seleccionado", "nums2"),
        numberedItem("Generacion de reporte HTML + PDF", "nums2"),

        // === OPCIONES ===
        new Paragraph({ children: [new PageBreak()] }),
        heading("4. Opciones adicionales", HeadingLevel.HEADING_1),

        heading("Restaurar CMS desde repos oficiales", HeadingLevel.HEADING_2),
        bullet("Checkbox activo por defecto", "bullets"),
        bullet("Descarga WordPress, plugins y temas limpios desde wordpress.org", "bullets"),
        bullet("Solo restaura plugins y temas ACTIVOS (segun la base de datos del backup)", "bullets"),
        bullet("Temas/plugins premium no disponibles en el repositorio se reportan como no verificables", "bullets"),

        heading("Generar PDF para cliente", HeadingLevel.HEADING_2),
        bullet("Crea un PDF resumen profesional con lenguaje no tecnico", "bullets"),
        bullet("Incluye: resumen ejecutivo, severidades, hallazgos principales y recomendaciones", "bullets"),

        heading("Nombre del archivo de salida", HeadingLevel.HEADING_2),
        para("Al terminar la limpieza, se muestra un dialogo donde puede personalizar el nombre del archivo .tar.gz de salida. Por defecto usa el nombre del backup original con \"-limpio\" al final."),

        heading("Post-limpieza", HeadingLevel.HEADING_2),
        bullet("Generar .tar.gz: Crea un archivo comprimido listo para importar en cPanel", "bullets"),
        bullet("Copiar a carpeta: Copia los archivos limpios a una ubicacion local", "bullets"),
        bullet("Solo reportes: No genera archivo de salida, solo los reportes HTML/PDF", "bullets"),

        // === CONFIGURACION ===
        heading("5. Configuracion", HeadingLevel.HEADING_1),

        heading("VirusTotal API", HeadingLevel.HEADING_2),
        para("La integracion con VirusTotal permite verificar archivos sospechosos contra 70+ motores antivirus."),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [2500, 6860],
          rows: [
            new TableRow({ children: [headerCell("Tipo de API", 2500), headerCell("Caracteristicas", 6860)] }),
            new TableRow({ children: [cell("Gratuita", 2500, {bold:true}), cell("500 consultas/dia, 4/min. Suficiente para confirmar detecciones sospechosas por hash.", 6860)] }),
            new TableRow({ children: [cell("Premium", 2500, {bold:true}), cell("Sin limites de consulta. Permite subir archivos completos para analisis profundo con todos los motores.", 6860)] }),
          ]
        }),
        para(""),
        boldPara("Modo Confirmar (rapido): ", "Solo consulta el hash SHA256 del archivo. No sube contenido. Ideal para verificar si un archivo ya es conocido como malicioso."),
        boldPara("Modo Profundo: ", "Sube los archivos sospechosos a VirusTotal para analisis completo. Mas lento pero detecta amenazas nuevas."),
        para(""),
        para("Como obtener la API key (gratis):"),
        numberedItem("Registrarse en virustotal.com", "nums3"),
        numberedItem("Ir a Perfil > API key", "nums3"),
        numberedItem("Copiar y pegar en la configuracion de cPacleanS", "nums3"),

        heading("Otros ajustes", HeadingLevel.HEADING_2),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [3000, 4360, 2000],
          rows: [
            new TableRow({ children: [headerCell("Campo", 3000), headerCell("Descripcion", 4360), headerCell("Por defecto", 2000)] }),
            new TableRow({ children: [cell("Tamano maximo archivo", 3000), cell("Archivos mas grandes se omiten del escaneo", 4360), cell("50 MB", 2000)] }),
            new TableRow({ children: [cell("Workers de escaneo", 3000), cell("Cantidad de CPUs a utilizar (slider)", 4360), cell("CPUs - 1", 2000)] }),
            new TableRow({ children: [cell("Restaurar CMS core", 3000), cell("Activar restauracion automatica desde repos", 4360), cell("Activado", 2000)] }),
          ]
        }),

        // === CUARENTENA ===
        new Paragraph({ children: [new PageBreak()] }),
        heading("6. Cuarentena segura", HeadingLevel.HEADING_1),
        para("cPacleanS nunca elimina archivos sin guardar una copia de seguridad primero."),
        bullet("Carpeta originales_intactos: Copias sin modificar de cada archivo antes de moverlo", "bullets"),
        bullet("Carpeta amenazas_removidas: Archivos extraidos del backup", "bullets"),
        bullet("En modo Normal, solo se mueven archivos con malware confirmado (webshells, backdoors, cryptominers)", "bullets"),
        bullet("Los archivos sospechosos se reportan pero NO se modifican ni eliminan", "bullets"),

        // === QUE DETECTA ===
        heading("7. Que detecta", HeadingLevel.HEADING_1),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [2800, 6560],
          rows: [
            new TableRow({ children: [headerCell("Categoria", 2800), headerCell("Ejemplos", 6560)] }),
            new TableRow({ children: [cell("WebShells", 2800, {bold:true}), cell("C99, R57, WSO, b374k, FilesMan", 6560)] }),
            new TableRow({ children: [cell("Backdoors", 2800, {bold:true}), cell("eval+base64, system+$_POST, proc_open", 6560)] }),
            new TableRow({ children: [cell("Inyecciones PHP", 2800, {bold:true}), cell("eval, assert, preg_replace /e, create_function", 6560)] }),
            new TableRow({ children: [cell("Ofuscacion", 2800, {bold:true}), cell("chr() encadenados, hex strings, gz+base64", 6560)] }),
            new TableRow({ children: [cell("Base de datos MySQL", 2800, {bold:true}), cell("PHP embebido en SQL, XSS almacenado, usuarios admin falsos", 6560)] }),
            new TableRow({ children: [cell("Correos", 2800, {bold:true}), cell("Phishing, adjuntos ejecutables, URLs con IP directa, vectores de reinfeccion", 6560)] }),
            new TableRow({ children: [cell("CMS", 2800, {bold:true}), cell("PHP en uploads, .htaccess malicioso, plugins vulnerables", 6560)] }),
            new TableRow({ children: [cell("JavaScript", 2800, {bold:true}), cell("Crypto-miners, eval+atob, scripts externos maliciosos", 6560)] }),
            new TableRow({ children: [cell(".htaccess", 2800, {bold:true}), cell("Redirecciones SEO spam, handlers PHP en imagenes", 6560)] }),
            new TableRow({ children: [cell("Reinfeccion", 2800, {bold:true}), cell("Descargas de pastebin, download+exec remoto, includes controlados", 6560)] }),
          ]
        }),

        // === REPORTES ===
        heading("8. Reportes", HeadingLevel.HEADING_1),
        para("Los reportes se generan automaticamente en la carpeta reportes/ junto al backup:"),
        bullet("HTML: Reporte interactivo completo con todos los hallazgos, contexto de codigo y graficas de severidad", "bullets"),
        bullet("PDF: Resumen ejecutivo para entregar al cliente, con lenguaje claro y recomendaciones de seguridad", "bullets"),

        // === RENDIMIENTO ===
        heading("9. Rendimiento estimado", HeadingLevel.HEADING_1),
        para("Tiempos aproximados con un equipo de 4 CPUs:"),
        new Table({
          width: { size: 9360, type: WidthType.DXA },
          columnWidths: [3120, 3120, 3120],
          rows: [
            new TableRow({ children: [headerCell("Tamano backup", 3120), headerCell("Archivos", 3120), headerCell("Tiempo aprox.", 3120)] }),
            new TableRow({ children: [cell("50 MB", 3120), cell("~3,000", 3120), cell("~1 minuto", 3120)] }),
            new TableRow({ children: [cell("350 MB", 3120), cell("~22,000", 3120), cell("~8 minutos", 3120)] }),
            new TableRow({ children: [cell("1.2 GB", 3120), cell("~52,000", 3120), cell("~20 minutos", 3120)] }),
          ]
        }),
        para("El rendimiento escala con la cantidad de CPUs disponibles. Equipos con 8+ CPUs seran significativamente mas rapidos."),

        // === SOPORTE ===
        heading("10. Soporte", HeadingLevel.HEADING_1),
        para("Repositorio del proyecto:"),
        new Paragraph({ spacing: { after: 120 }, children: [
          new ExternalHyperlink({
            children: [new TextRun({ text: "github.com/sotadev-agency/proyectos-ia", style: "Hyperlink", size: 22, font: "Arial" })],
            link: "https://github.com/sotadev-agency/proyectos-ia.git",
          })
        ]}),
        para("Para reportar fallas o solicitar mejoras, consulte la guia GUIA_REPORTAR_FALLAS.md incluida en el proyecto."),
      ]
    }
  ]
});

const OUTPUT = "C:\\Users\\SSW\\Documents\\limpiador_malware\\MANUAL_cPacleanS.docx";
Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(OUTPUT, buffer);
  console.log("OK: " + OUTPUT);
  console.log("Size: " + Math.round(buffer.length / 1024) + " KB");
});
