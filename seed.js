/**
 * EncomPR — Seed Data
 * Genera datos de demostración para el sistema
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function writeJSON(file, data) {
  fs.writeFileSync(path.join(DATA_DIR, file), JSON.stringify(data, null, 2), 'utf8');
}

function uuid() { return crypto.randomUUID(); }
function hash(pw) { return crypto.createHash('sha256').update(pw).digest('hex'); }
function daysAgo(n) { return new Date(Date.now() - n * 86400000).toISOString(); }

console.log('Generando datos de demostración...\n');

// ── USERS ──
const adminId = uuid();
const editor1Id = uuid();
const editor2Id = uuid();
const editor3Id = uuid();

const users = [
  { id: adminId, name: 'Javi', email: 'javier@encom.es', passwordHash: hash('encom2024'), role: 'admin', createdAt: daysAgo(365) },
  { id: editor1Id, name: 'Laura Martínez', email: 'laura@encom.es', passwordHash: hash('editor2024'), role: 'editor', createdAt: daysAgo(200) },
  { id: editor2Id, name: 'Carlos Ruiz', email: 'carlos@encom.es', passwordHash: hash('editor2024'), role: 'editor', createdAt: daysAgo(180) },
  { id: editor3Id, name: 'Ana Beltrán', email: 'ana@encom.es', passwordHash: hash('editor2024'), role: 'editor', createdAt: daysAgo(150) },
  { id: uuid(), name: 'Maria Tinoco', email: 'maria.tinoco@valenciagamecity.com', passwordHash: hash('123456'), role: 'editor', createdAt: daysAgo(10) },
  { id: uuid(), name: 'Jon Fermin', email: 'jonfermin@encom.es', passwordHash: hash('123456'), role: 'editor', createdAt: daysAgo(10) },
];
writeJSON('users.json', users);
console.log(`✓ ${users.length} usuarios creados`);

// ── MEDIOS ──
const medios = [
  { id: uuid(), nombre: 'María García López', email: 'maria.garcia@levante-emv.com', medio: 'Levante-EMV', cargo: 'Redactora de Cultura', tematicas: ['cultura', 'eventos', 'música'], region: 'Comunitat Valenciana', telefono: '612345678', notas: 'Contacto principal para cultura en Levante', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(15) }], publicaciones: 3, tasaPublicacion: 75, createdAt: daysAgo(300), updatedAt: daysAgo(5) },
  { id: uuid(), nombre: 'Pablo Fernández', email: 'pfernandez@lasprovincias.es', medio: 'Las Provincias', cargo: 'Jefe de sección Ocio', tematicas: ['eventos', 'lifestyle', 'cultura'], region: 'Comunitat Valenciana', telefono: '623456789', notas: '', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(20) }], publicaciones: 5, tasaPublicacion: 83, createdAt: daysAgo(280), updatedAt: daysAgo(3) },
  { id: uuid(), nombre: 'Lucía Navarro', email: 'lucia.navarro@elpais.com', medio: 'El País', cargo: 'Periodista de Cultura', tematicas: ['cultura', 'música', 'eventos'], region: 'Nacional', telefono: '634567890', notas: 'Interesada en festivales grandes', historialEnvios: [], publicaciones: 1, tasaPublicacion: 25, createdAt: daysAgo(250), updatedAt: daysAgo(10) },
  { id: uuid(), nombre: 'Andrés Molina', email: 'amolina@elmundo.es', medio: 'El Mundo', cargo: 'Redactor', tematicas: ['eventos', 'tecnología', 'cultura'], region: 'Nacional', telefono: '645678901', notas: '', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(30) }], publicaciones: 2, tasaPublicacion: 50, createdAt: daysAgo(240), updatedAt: daysAgo(8) },
  { id: uuid(), nombre: 'Elena Ruiz Sánchez', email: 'elena@vandal.net', medio: 'Vandal', cargo: 'Editora de Eventos Gaming', tematicas: ['gaming', 'tecnología', 'eventos'], region: 'Nacional', telefono: '656789012', notas: 'Cubre ferias y eventos gaming', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(10) }], publicaciones: 4, tasaPublicacion: 80, createdAt: daysAgo(220), updatedAt: daysAgo(2) },
  { id: uuid(), nombre: 'David Torres', email: 'david@3djuegos.com', medio: '3DJuegos', cargo: 'Redactor senior', tematicas: ['gaming', 'tecnología'], region: 'Nacional', telefono: '667890123', notas: '', historialEnvios: [], publicaciones: 2, tasaPublicacion: 40, createdAt: daysAgo(200), updatedAt: daysAgo(15) },
  { id: uuid(), nombre: 'Sara López', email: 'sara.lopez@vidaextra.com', medio: 'Vida Extra', cargo: 'Periodista', tematicas: ['gaming', 'eventos', 'tecnología'], region: 'Nacional', telefono: '678901234', notas: 'Interesada en indie gaming', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(25) }], publicaciones: 3, tasaPublicacion: 60, createdAt: daysAgo(190), updatedAt: daysAgo(7) },
  { id: uuid(), nombre: 'Miguel Ángel Romero', email: 'maromero@valenciaplaza.com', medio: 'Valencia Plaza', cargo: 'Director de contenidos', tematicas: ['cultura', 'eventos', 'lifestyle'], region: 'Valencia', telefono: '689012345', notas: 'Alto impacto local', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(5) }], publicaciones: 6, tasaPublicacion: 90, createdAt: daysAgo(350), updatedAt: daysAgo(1) },
  { id: uuid(), nombre: 'Carmen Vidal', email: 'carmen.vidal@europapress.es', medio: 'Europa Press', cargo: 'Corresponsal Valencia', tematicas: ['eventos', 'cultura', 'música'], region: 'Nacional', telefono: '690123456', notas: 'Agencia — alto alcance', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(12) }], publicaciones: 7, tasaPublicacion: 88, createdAt: daysAgo(320), updatedAt: daysAgo(4) },
  { id: uuid(), nombre: 'Javier Moreno', email: 'jmoreno@efe.com', medio: 'Agencia EFE', cargo: 'Redactor cultural', tematicas: ['cultura', 'eventos'], region: 'Nacional', telefono: '601234567', notas: 'Contactar con antelación', historialEnvios: [], publicaciones: 4, tasaPublicacion: 66, createdAt: daysAgo(300), updatedAt: daysAgo(20) },
  { id: uuid(), nombre: 'Patricia Gómez', email: 'patricia@mondosonoro.com', medio: 'Mondo Sonoro', cargo: 'Editora Valencia', tematicas: ['música', 'cultura', 'eventos'], region: 'Comunitat Valenciana', telefono: '612345098', notas: 'Especialista en música independiente', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(8) }], publicaciones: 5, tasaPublicacion: 71, createdAt: daysAgo(270), updatedAt: daysAgo(3) },
  { id: uuid(), nombre: 'Roberto Martín', email: 'roberto@igamesplay.com', medio: 'iGamesPlay', cargo: 'Director', tematicas: ['gaming', 'tecnología', 'eventos'], region: 'Nacional', telefono: '623450987', notas: '', historialEnvios: [], publicaciones: 1, tasaPublicacion: 33, createdAt: daysAgo(180), updatedAt: daysAgo(30) },
  { id: uuid(), nombre: 'Isabel Herrera', email: 'iherrera@abc.es', medio: 'ABC', cargo: 'Sección Cultura', tematicas: ['cultura', 'eventos', 'lifestyle'], region: 'Nacional', telefono: '634560987', notas: '', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(18) }], publicaciones: 2, tasaPublicacion: 40, createdAt: daysAgo(260), updatedAt: daysAgo(12) },
  { id: uuid(), nombre: 'Tomás Pascual', email: 'tomas@revistagq.es', medio: 'GQ España', cargo: 'Redactor Lifestyle', tematicas: ['lifestyle', 'eventos', 'cultura'], region: 'Nacional', telefono: '645670987', notas: 'Interés en eventos premium', historialEnvios: [], publicaciones: 1, tasaPublicacion: 25, createdAt: daysAgo(150), updatedAt: daysAgo(40) },
  { id: uuid(), nombre: 'Raquel Díaz', email: 'raquel@culturplaza.com', medio: 'Culturplaza', cargo: 'Periodista cultural', tematicas: ['cultura', 'música', 'eventos'], region: 'Valencia', telefono: '656780987', notas: 'Medio digital valenciano de referencia', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(6) }], publicaciones: 8, tasaPublicacion: 95, createdAt: daysAgo(340), updatedAt: daysAgo(2) },
  { id: uuid(), nombre: 'Alejandro Gil', email: 'agil@meristation.com', medio: 'Meristation', cargo: 'Editor eventos', tematicas: ['gaming', 'tecnología', 'eventos'], region: 'Nacional', telefono: '667890987', notas: '', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(22) }], publicaciones: 3, tasaPublicacion: 50, createdAt: daysAgo(230), updatedAt: daysAgo(9) },
  { id: uuid(), nombre: 'Nuria Ferrer', email: 'nuria@timeout.es', medio: 'Time Out Valencia', cargo: 'Editora Valencia', tematicas: ['eventos', 'lifestyle', 'cultura', 'música'], region: 'Valencia', telefono: '678900987', notas: 'Guía de ocio — alto impacto local', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(4) }], publicaciones: 9, tasaPublicacion: 92, createdAt: daysAgo(310), updatedAt: daysAgo(1) },
  { id: uuid(), nombre: 'Francisco Ibáñez', email: 'fibañez@expansion.com', medio: 'Expansión', cargo: 'Sector entretenimiento', tematicas: ['eventos', 'tecnología'], region: 'Nacional', telefono: '689010987', notas: 'Enfoque económico/negocio', historialEnvios: [], publicaciones: 0, tasaPublicacion: 0, createdAt: daysAgo(100), updatedAt: daysAgo(50) },
  { id: uuid(), nombre: 'Laura Chen', email: 'laura.chen@gamesindustry.biz', medio: 'GamesIndustry.biz', cargo: 'EU Correspondent', tematicas: ['gaming', 'tecnología', 'eventos'], region: 'Internacional', telefono: '', notas: 'Medio internacional B2B gaming', historialEnvios: [], publicaciones: 1, tasaPublicacion: 20, createdAt: daysAgo(120), updatedAt: daysAgo(45) },
  { id: uuid(), nombre: 'Antonio Blasco', email: 'ablasco@elperiodic.com', medio: 'El Periòdic', cargo: 'Redactor', tematicas: ['eventos', 'cultura', 'música'], region: 'Comunitat Valenciana', telefono: '690120987', notas: '', historialEnvios: [{ notaId: 'demo', fecha: daysAgo(14) }], publicaciones: 4, tasaPublicacion: 57, createdAt: daysAgo(250), updatedAt: daysAgo(6) },
];
writeJSON('medios.json', medios);
console.log(`✓ ${medios.length} contactos de medios creados`);

// ── NOTAS DE PRENSA ──
const nota1Id = uuid();
const nota2Id = uuid();
const nota3Id = uuid();

const notas = [
  {
    id: nota1Id,
    proyecto: 'OWN Valencia',
    titular: 'OWN Valencia 2026 anuncia su programación más ambiciosa con más de 150 artistas',
    subtitulo: 'El festival de referencia de la Comunitat Valenciana celebra su nueva edición del 12 al 14 de junio en la Ciudad de las Artes',
    cuerpo: `OWN Valencia, el festival insignia de Encom, ha desvelado hoy el cartel completo de su edición 2026, que contará con más de 150 artistas nacionales e internacionales distribuidos en 5 escenarios.\n\nLa Ciudad de las Artes y las Ciencias de Valencia volverá a acoger del 12 al 14 de junio uno de los eventos musicales más importantes del panorama nacional, con una propuesta que fusiona géneros y experiencias.\n\nEntre los nombres confirmados destacan artistas de primer nivel que abarcan desde el indie y el pop alternativo hasta la electrónica y el urban. El festival también incorpora este año un escenario dedicado a artistas emergentes valencianos.\n\n"Queremos que OWN Valencia sea mucho más que un festival: es una experiencia cultural que pone a Valencia en el mapa internacional de los grandes eventos", afirma Javi, CEO de Encom.\n\nLas entradas se pondrán a la venta el próximo 1 de abril a través de la web oficial, con un precio de lanzamiento de 89€ el abono de tres días.`,
    datosClaveRaw: '150+ artistas, 5 escenarios, 3 días (12-14 junio), Ciudad de las Artes, 35.000 asistentes esperados, 89€ abono lanzamiento',
    citas: '"Queremos que OWN Valencia sea mucho más que un festival: es una experiencia cultural que pone a Valencia en el mapa internacional de los grandes eventos" — Javi, CEO de Encom',
    contactoPrensa: 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000',
    materialesAdjuntos: 'https://drive.google.com/encom/own2026-press-kit',
    notaEjemplo: '',
    plantilla: '',
    estado: 'validada',
    autorId: adminId,
    autorNombre: 'Javi',
    validaciones: [
      { id: uuid(), accion: 'cambios', comentario: 'Añadir dato de asistentes del año pasado', validadorNombre: 'Marketing OWN', fecha: daysAgo(10) },
      { id: uuid(), accion: 'aprobar', comentario: 'Todo correcto, aprobada para envío', validadorNombre: 'Marketing OWN', fecha: daysAgo(8) }
    ],
    publicaciones: [
      { id: uuid(), medio: 'Levante-EMV', url: 'https://levante-emv.com/own-valencia-2026', fecha: daysAgo(5) },
      { id: uuid(), medio: 'Valencia Plaza', url: 'https://valenciaplaza.com/own-festival-2026', fecha: daysAgo(4) },
      { id: uuid(), medio: 'Europa Press', url: 'https://europapress.es/comunitat/own-2026', fecha: daysAgo(4) },
    ],
    envios: [
      { id: uuid(), mediosIds: medios.slice(0, 10).map(m => m.id), fecha: daysAgo(7), enviadoPor: 'Javi', via: 'manual' }
    ],
    createdAt: daysAgo(20),
    updatedAt: daysAgo(4),
  },
  {
    id: nota2Id,
    proyecto: 'Valencia Game City',
    titular: 'Valencia Game City 2026: la industria del videojuego se da cita en Valencia del 23 al 25 de octubre',
    subtitulo: 'La tercera edición del evento gaming de referencia en el Mediterráneo amplía su espacio y programa',
    cuerpo: `Valencia Game City (VGC) vuelve con su tercera edición convertida en el evento de referencia del sector gaming en el arco mediterráneo. Del 23 al 25 de octubre, Feria Valencia acogerá un programa que combina zona de exposición, torneos esports, área indie y conferencias profesionales.\n\nEste año, VGC duplica su superficie expositiva hasta los 15.000 m² y espera superar los 25.000 visitantes. El programa profesional B2B contará con más de 40 ponentes internacionales.\n\nEntre las novedades de 2026 destaca la VGC Indie Showcase, un espacio dedicado a estudios independientes españoles con mentoring y oportunidades de publishing.\n\n"Valencia tiene un ecosistema gaming en crecimiento y VGC es el punto de encuentro natural para la comunidad y la industria", señala Javi, CEO de Encom.`,
    datosClaveRaw: '3ª edición, 23-25 octubre, Feria Valencia, 15.000 m², 25.000 visitantes esperados, 40+ ponentes B2B, VGC Indie Showcase nuevo',
    citas: '"Valencia tiene un ecosistema gaming en crecimiento y VGC es el punto de encuentro natural para la comunidad y la industria" — Javi, CEO de Encom',
    contactoPrensa: 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000',
    materialesAdjuntos: 'https://drive.google.com/encom/vgc2026-press-kit',
    notaEjemplo: '',
    plantilla: '',
    estado: 'enviada',
    autorId: editor1Id,
    autorNombre: 'Laura Martínez',
    validaciones: [
      { id: uuid(), accion: 'aprobar', comentario: 'Perfecto, listo para envío', validadorNombre: 'Equipo VGC', fecha: daysAgo(12) }
    ],
    publicaciones: [
      { id: uuid(), medio: 'Vandal', url: 'https://vandal.net/vgc-2026', fecha: daysAgo(6) },
    ],
    envios: [
      { id: uuid(), mediosIds: medios.filter(m => m.tematicas.includes('gaming')).map(m => m.id), fecha: daysAgo(9), enviadoPor: 'Laura Martínez', via: 'manual' }
    ],
    createdAt: daysAgo(18),
    updatedAt: daysAgo(6),
  },
  {
    id: nota3Id,
    proyecto: 'IDASFEST',
    titular: 'IDASFEST aterriza en Valencia: el nuevo festival urbano que fusiona música, arte y gastronomía',
    subtitulo: 'La primera edición de IDASFEST tendrá lugar el 5 de septiembre en los Jardines del Turia',
    cuerpo: `Encom presenta IDASFEST, un nuevo concepto de festival urbano que nace con la vocación de convertirse en referente del entretenimiento experiencial. La primera edición se celebrará el 5 de septiembre en los Jardines del Turia.\n\nIDASFEST propone una jornada que combina actuaciones musicales en directo, instalaciones de arte urbano, food trucks de la mejor gastronomía valenciana y zonas de experiencias interactivas.\n\nEl festival está diseñado para un público amplio, con propuestas para todos los gustos: desde DJ sets y conciertos acústicos hasta talleres creativos y zona infantil.\n\nLas entradas ya están disponibles a un precio de 25€ en la web oficial.`,
    datosClaveRaw: '1ª edición, 5 septiembre, Jardines del Turia, 10.000 asistentes esperados, 25€ entrada, música + arte + gastronomía',
    citas: '',
    contactoPrensa: 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000',
    materialesAdjuntos: '',
    notaEjemplo: '',
    plantilla: '',
    estado: 'borrador',
    autorId: editor2Id,
    autorNombre: 'Carlos Ruiz',
    validaciones: [],
    publicaciones: [],
    envios: [],
    createdAt: daysAgo(5),
    updatedAt: daysAgo(2),
  }
];
writeJSON('notas.json', notas);
console.log(`✓ ${notas.length} notas de prensa creadas`);

// ── PLANTILLAS ──
const plantillas = [
  {
    id: uuid(), nombre: 'Festival Musical', tipo: 'OWN Valencia',
    contenido: {
      titular: '[NOMBRE FESTIVAL] [AÑO]: [gancho principal]',
      subtitulo: 'El festival [X] celebra su [Nª] edición del [FECHAS] en [LUGAR]',
      cuerpo: '[Párrafo 1: Qué y cuándo]\n\n[Párrafo 2: Detalles del programa/cartel]\n\n[Párrafo 3: Novedades de esta edición]\n\n[Párrafo 4: Cita del CEO/organizador]\n\n[Párrafo 5: Datos prácticos (entradas, precios, acceso)]',
      contactoPrensa: 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000'
    },
    createdAt: daysAgo(100)
  },
  {
    id: uuid(), nombre: 'Evento Gaming', tipo: 'Valencia Game City',
    contenido: {
      titular: '[EVENTO] [AÑO]: [dato impactante sobre la edición]',
      subtitulo: 'La [Nª] edición de [EVENTO] se celebrará del [FECHAS] en [LUGAR]',
      cuerpo: '[Párrafo 1: Presentación del evento y fechas]\n\n[Párrafo 2: Programa y actividades principales]\n\n[Párrafo 3: Zona profesional/B2B]\n\n[Párrafo 4: Novedades y cita del organizador]\n\n[Párrafo 5: Info práctica]',
      contactoPrensa: 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000'
    },
    createdAt: daysAgo(100)
  },
  {
    id: uuid(), nombre: 'Anuncio General', tipo: 'Encom',
    contenido: {
      titular: 'Encom [acción]: [qué]',
      subtitulo: '[Contexto breve que amplía el titular]',
      cuerpo: '[Párrafo 1: Noticia principal]\n\n[Párrafo 2: Contexto y detalles]\n\n[Párrafo 3: Implicaciones y próximos pasos]\n\n[Párrafo 4: Cita]',
      contactoPrensa: 'Departamento de Comunicación Encom — prensa@encom.es — 960 000 000'
    },
    createdAt: daysAgo(100)
  }
];
writeJSON('plantillas.json', plantillas);
console.log(`✓ ${plantillas.length} plantillas creadas`);

// ── SESSIONS, NOTIFICATIONS, VALIDATION LINKS ──
writeJSON('sessions.json', []);
writeJSON('notifications.json', [
  { id: uuid(), type: 'validacion', notaId: nota1Id, message: 'Nota OWN Valencia 2026 aprobada por Marketing OWN', read: true, createdAt: daysAgo(8) },
  { id: uuid(), type: 'publicacion', notaId: nota1Id, message: 'Nueva publicación en Levante-EMV de la nota OWN Valencia', read: false, createdAt: daysAgo(5) },
  { id: uuid(), type: 'validacion', notaId: nota2Id, message: 'Nota VGC 2026 aprobada por Equipo VGC', read: true, createdAt: daysAgo(12) },
]);
writeJSON('validation_links.json', []);
writeJSON('mailchimp_config.json', {});

console.log(`✓ Datos auxiliares generados`);
console.log(`\n═══════════════════════════════════════`);
console.log(`  Seed completado con éxito`);
console.log(`  Admin: javier@encom.es / encom2024`);
console.log(`  Editores: laura/carlos/ana @encom.es / editor2024`);
console.log(`═══════════════════════════════════════\n`);
